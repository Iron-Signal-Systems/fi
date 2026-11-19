// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 ISOLATED C220 CLONE: P6 native source/relational SQL, six real backend
// connections (ordered source parent plus five independent child writers).
// No new pending_source_record staging, no P7 preparer bridge, no alternate
// relational projectors. Failure renders this disposable SQL clone unusable;
// never resume it or treat partially committed parents as a checkpoint.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "os"
    "strings"
    "sync"
    "time"

    "github.com/jackc/pgx/v5"
)

// C1 retains P6's bounded capacity handoffs: a family may have four
// SQL buffers in flight. Backpressure consumes ONE oldest acknowledgment,
// not the entire queue, so the SQL lane never waits for a new burst.
const privateC1MaxFamilyHandoffsInFlight = 4

// A source ACK can be observed by every dependent family without consuming
// the result. Closing done publishes err to all readers (Go channel happens-before).
type privateC1SourceAck struct {
    done chan struct{}
    err error
}
type privateC1SourceJob struct {
    rows []privateP6Record
    ack *privateC1SourceAck
}
type privateC1SQLJob struct {
    rows []privateP6Record
    source *privateC1SourceAck
    done chan error
}
type privateC1SQLLane struct {
    family privateP6Family
    module privateC1FamilyModule
    conn *pgx.Conn
    jobs chan privateC1SQLJob
    outstanding []chan error // owner: canonical reader goroutine only
    committed int64
    handoffs int64
    err error
    sqlWall time.Duration
    sourceParentWaitWall time.Duration
    identityLookup time.Duration
    projectionWall time.Duration
    commitWall time.Duration
    backpressureWaits int64 // owner: signed reader goroutine
    backpressureWaitWall time.Duration
    // Only this lane goroutine writes these original SecurityBulk counters.
    // They are aggregates of P6's existing projector/COPY measurements;
    // no extra SQL, source staging, or per-row timer is introduced.
    securityCopies securityBulkTimingCounters
}
type privateC1FiveSQL struct {
    parent *pgx.Conn
    sourceJobs chan privateC1SourceJob
    sourceOutstanding []*privateC1SourceAck // signed reader only
    sourceLast *privateC1SourceAck // latest ordered parent commit fence
    sourceWG sync.WaitGroup
    sourceBackpressureWaits int64
    sourceBackpressureWall time.Duration
    lanes [privateP6FamilyCount]*privateC1SQLLane
    sourceID string
    ctx context.Context
    cancel context.CancelFunc
    wg sync.WaitGroup
    parentRows int64
    parentHandoffs int64
    parentSQLWall time.Duration
    closed bool
    failed error
}

func privateC1Enabled() bool {
    return os.Getenv("FI_W512_C1_P6_DIRECT")=="1" &&
        os.Getenv("FI_W512_P7_SQL_WRITERS")=="" &&
        os.Getenv("FI_W512_P8_REUSE")=="" &&
        os.Getenv("FI_W512_P9_DIRECT_STREAM")=="" &&
        privateP6Selected()
}

func privateC1CloneConnection(ctx context.Context,dsn,expectedPGDATA string)(*pgx.Conn,int64,error){
    if dsn==""||expectedPGDATA==""||
        !strings.HasPrefix(expectedPGDATA,"/home/jwood/fi-window-bench-w512-family-p3-")||
        !strings.HasSuffix(expectedPGDATA,"/clone-w512-2g/data") ||
        !strings.Contains(dsn,"sslmode=disable")||
        !strings.Contains(dsn,"user=fi_ingest") ||
        !strings.Contains(dsn,"host=/var/tmp/fi-window-chunks-family-p3-") {
        return nil,0,errors.New("FI C1: exact private C220 clone DSN/PGDATA required")
    }
    conn,err:=pgx.Connect(ctx,dsn)
    if err!=nil{return nil,0,err}
    // The C220 runner has already checked the exact private PGDATA using
    // the clone's existing owner login. Do not grant pg_read_all_settings
    // to fi_ingest merely so this session can query data_directory again.
    // This worker only verifies the trusted clone socket, role, recovery
    // state, and distinct PostgreSQL backend identity.
    var user string
    var recovery bool
    var pid int64
    err=conn.QueryRow(ctx,`SELECT current_user,
pg_is_in_recovery(),pg_backend_pid()::bigint`).Scan(&user,&recovery,&pid)
    if err!=nil||user!="fi_ingest"||recovery||pid<=0{
        conn.Close(context.Background())
        return nil,0,fmt.Errorf("FI C1: unexpected clone session role=%q standby=%v pid=%d err=%v",user,recovery,pid,err)
    }
    return conn,pid,nil
}

func newPrivateC1FiveSQL(ctx context.Context,dsn,pgdata,sourceID string)(*privateC1FiveSQL,error){
    if !privateC1Enabled()||ctx==nil||sourceID==""{
        return nil,errors.New("FI C1: private P6 five-writer feature not selected")
    }
    owner,cancel:=context.WithCancel(ctx)
    w:=&privateC1FiveSQL{ctx:owner,cancel:cancel,sourceID:sourceID,
        sourceJobs:make(chan privateC1SourceJob,2)}
    cleanup:=func(){
        cancel()
        if w.parent!=nil { _=w.parent.Close(context.Background()) }
        for _,lane:=range w.lanes {
            if lane!=nil&&lane.conn!=nil {_=lane.conn.Close(context.Background())}
        }
    }
    parent,parentPID,err:=privateC1CloneConnection(ctx,dsn,pgdata)
    if err!=nil{cleanup();return nil,err}
    w.parent=parent
    pids:=map[int64]bool{parentPID:true}
    for i:=range w.lanes{
        conn,pid,e:=privateC1CloneConnection(ctx,dsn,pgdata)
        if e!=nil{cleanup();return nil,e}
        if pids[pid]{
            conn.Close(context.Background());cleanup()
            return nil,errors.New("FI C1: duplicate backend PID, five independent connections required")
        }
        pids[pid]=true
        w.lanes[i]=&privateC1SQLLane{family:privateP6Family(i),
            module:privateC1SQLModules[i],
            conn:conn,jobs:make(chan privateC1SQLJob,2)}
    }
    // Exactly one ordered source writer, plus five independent family writers.
    // The signed reader no longer executes PostgreSQL COPY itself.
    w.sourceWG.Add(1)
    go w.runSource()
    for _,lane:=range w.lanes{
        w.wg.Add(1)
        go w.runLane(lane)
    }
    fmt.Printf("FI C1 P6 NATIVE SQL BACKENDS parent=1 family_writers=5 distinct_pids=%d clone_only=true\n",len(pids))
    return w,nil
}

func privateC1AwaitSource(ctx context.Context, ack *privateC1SourceAck) error {
    if ctx==nil||ack==nil{return errors.New("FI C1: missing ordered source-parent fence")}
    select{
    case <-ctx.Done():return ctx.Err()
    case <-ack.done:return ack.err
    }
}

func(w *privateC1FiveSQL) runSource(){
    defer w.sourceWG.Done()
    var failed error
    for job:=range w.sourceJobs {
        if failed==nil {failed=w.writeSource(w.ctx,job.rows)}
        job.ack.err=failed
        close(job.ack.done)
    }
}

func(w *privateC1FiveSQL) runLane(lane *privateC1SQLLane){
    defer w.wg.Done()
    for job:=range lane.jobs {
        // Distinguish waiting on parent custody from real family SQL time.
        // Otherwise this overlap would appear as an artificial SQL slowdown.
        parentWaitStarted:=time.Now()
        err:=privateC1AwaitSource(w.ctx,job.source)
        lane.sourceParentWaitWall+=time.Since(parentWaitStarted)
        if err==nil {
            sqlStarted:=time.Now()
            err=w.writeFamily(w.ctx,lane,job.rows)
            lane.sqlWall+=time.Since(sqlStarted)
        }
        if err==nil{
            lane.committed+=int64(len(job.rows))
            lane.handoffs++
        }else{
            lane.err=err
        }
        job.done<-err
        close(job.done)
        // After failure, each later job gets the SAME error. This leaves
        // every completion channel signaled and avoids blocked Finish.
    }
}

// P6's standard typed-window path installs these original COPY states and
// caches before invoking any child projector. Each concurrent C1 family
// transaction needs its own copies: never share a mutable COPY buffer across
// five SQL writers, and NEVER enable SendBatch on privateProjectionTx.
func privateC1BoundedProjectorContext(ctx context.Context)(
    context.Context,*contentHashCopyState,*aceCopyState,*usnChangeCopyState){
    ctx=context.WithValue(ctx,ntfsObjectCacheContextKey{},newNTFSObjectCache())
    ctx=context.WithValue(ctx,ntfsScopeIdentityCacheContextKey{},newNTFSScopeIdentityCache())
    hashCopy:=newContentHashCopyState()
    aceCopy:=newACECopyState()
    usnCopy:=newUSNChangeCopyState()
    ctx=context.WithValue(ctx,contentHashCopyContextKey{},hashCopy)
    ctx=context.WithValue(ctx,aceCopyContextKey{},aceCopy)
    ctx=context.WithValue(ctx,usnChangeCopyContextKey{},usnCopy)
    ctx=context.WithValue(ctx,ntfsStageTimingContextKey{},&ntfsStageTimingCounters{})
    return ctx,hashCopy,aceCopy,usnCopy
}

func(w *privateC1FiveSQL) writeFamily(ctx context.Context,lane *privateC1SQLLane,rows []privateP6Record)error{
    if lane.err!=nil{return lane.err}
    if err:=ctx.Err();err!=nil{return err}
    tx,err:=lane.conn.Begin(ctx)
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    profile:=&ingestStageProfile{}
    coordinator,err:=newPrivateP6SQLCoordinator(privateProjectionTx{Tx:tx},
        w.sourceID,profile)
    if err!=nil{return err}
    writeCtx,hashCopy,aceCopy,usnCopy:=privateC1BoundedProjectorContext(ctx)
    // Each lane owns its family-specific P6 projection module. The common
    // coordinator is used only for the exact signed (batch,ordinal) FK lookup.
    // The original central five-family SQL switch is not on this path.
    lookupTime,projectTime,e:=lane.module.execute(coordinator,writeCtx,rows)
    lane.identityLookup+=lookupTime
    lane.projectionWall+=projectTime
    if e!=nil{return e}
    if lane.family==privateP6Security {
        // The original P6 projector already populated this per-handoff
        // profile. Accumulate those counters before it goes out of scope.
        // No instrumentation is placed inside event or field COPY loops.
        counters:=profile.SecurityBulk
        s:=&lane.securityCopies
        s.Batches+=counters.Batches
        s.Events+=counters.Events
        s.Scopes+=counters.Scopes
        s.Fields+=counters.Fields
        s.SourceBytes+=counters.SourceBytes
        s.Prepare+=counters.Prepare
        s.SourceCopy+=counters.SourceCopy
        s.IDLookup+=counters.IDLookup
        s.EventCopy+=counters.EventCopy
        s.ChildPrepare+=counters.ChildPrepare
        s.ScopeCopy+=counters.ScopeCopy
        s.FieldCopy+=counters.FieldCopy
    }
    // The same privateProjectionTx rewrites all five family's COPY
    // targets into fi_recovery_projection. Drain *before* SQL COMMIT:
    // pending hashes/ACEs/USN changes and reasons are real FK children.
    projector:=privateProjectionTx{Tx:tx}
    if err=usnCopy.flushAll(writeCtx,projector);err!=nil{
        return fmt.Errorf("FI C1: USN/reason child COPY: %w",err)
    }
    if err=hashCopy.flush(writeCtx,projector);err!=nil{
        return fmt.Errorf("FI C1: content-hash child COPY: %w",err)
    }
    if err=aceCopy.flushAll(writeCtx,projector);err!=nil{
        return fmt.Errorf("FI C1: DACL/SACL child COPY: %w",err)
    }
    startedCommit:=time.Now()
    err=tx.Commit(ctx)
    lane.commitWall+=time.Since(startedCommit)
    if err!=nil{return err}
    // DEVELOPMENT FAILURE INJECTION: the File transaction is deliberately
    // already durable when this error is returned. Finish/MarkTyped must
    // refuse the incomplete generation; the next attempt must fail its
    // clean-start guard unless it runs from a new, verified private clone.
    // This never runs without the exact C1 private clone selection gate.
    if privateC1PostCommitFailpoint(lane.family) {
        return errors.New("FI C1 DEVELOPMENT INJECTION: File SQL committed; typed checkpoint must not advance; discard dirty clone")
    }
    return nil
}


// privateC1PostCommitFailpoint is deliberately restricted to C1's private
// clone. It is NOT a production SQL behavior or an automatic retry.
func privateC1PostCommitFailpoint(f privateP6Family) bool {
    return f==privateP6File && privateC1Enabled() &&
        os.Getenv("FI_C1_DEV_FAIL_AFTER_FILE_SQL_COMMIT")=="1"
}

// Only the source goroutine uses the ordered PostgreSQL parent connection.
func(w *privateC1FiveSQL) writeSource(ctx context.Context,rows []privateP6Record)error{
    startedSource:=time.Now()
    tx,err:=w.parent.Begin(ctx)
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    coordinator,err:=newPrivateP6SQLCoordinator(privateProjectionTx{Tx:tx},
        w.sourceID,&ingestStageProfile{})
    if err==nil{err=coordinator.Source(ctx,rows)}
    if err==nil{err=tx.Commit(ctx)}
    if err!=nil{return fmt.Errorf("FI C1: ordered P6 source parent failed: %w",err)}
    w.parentRows+=int64(len(rows))
    w.parentHandoffs++
    w.parentSQLWall+=time.Since(startedSource)
    return nil
}

// Source enqueues signed-order parent rows; there is one PostgreSQL
// writer, no staging table, and at most four bounded in-flight handoffs.
// Child writers await the precise most recent parent ACK in their own lanes.
func(w *privateC1FiveSQL) Source(ctx context.Context,rows []privateP6Record)error{
    if w==nil||w.closed||len(rows)==0||w.sourceJobs==nil{
        return errors.New("FI C1: invalid source parent handoff")
    }
    if w.failed!=nil{return w.failed}
    if len(w.sourceOutstanding)>=privateC1MaxFamilyHandoffsInFlight {
        started:=time.Now()
        w.sourceBackpressureWaits++
        err:=w.waitNextSource(ctx)
        w.sourceBackpressureWall+=time.Since(started)
        if err!=nil{return err}
    }
    ack:=&privateC1SourceAck{done:make(chan struct{})}
    job:=privateC1SourceJob{rows:rows,ack:ack}
    select {
    case <-ctx.Done():return ctx.Err()
    case <-w.ctx.Done():return w.ctx.Err()
    case w.sourceJobs<-job:
    }
    w.sourceOutstanding=append(w.sourceOutstanding,ack)
    w.sourceLast=ack
    return nil
}

func(w *privateC1FiveSQL) waitNextSource(ctx context.Context)error{
    if w==nil||ctx==nil||len(w.sourceOutstanding)==0{
        return errors.New("FI C1: invalid ordered parent acknowledgment")
    }
    ack:=w.sourceOutstanding[0]
    if err:=privateC1AwaitSource(ctx,ack);err!=nil{
        w.failed=fmt.Errorf("FI C1: ordered source parent commit: %w",err)
        return w.failed
    }
    w.sourceOutstanding[0]=nil
    w.sourceOutstanding=w.sourceOutstanding[1:]
    return nil
}

func(w *privateC1FiveSQL) WaitSource(ctx context.Context)error{
    if w==nil{return errors.New("FI C1: missing ordered source writer")}
    for len(w.sourceOutstanding)>0{
        if err:=w.waitNextSource(ctx);err!=nil{return err}
    }
    return nil
}

func(w *privateC1FiveSQL) Family(ctx context.Context,f privateP6Family,rows []privateP6Record)error{
    if w==nil||w.closed||f>=privateP6FamilyCount||len(rows)==0{
        return errors.New("FI C1: invalid P6 family handoff")
    }
    if w.failed!=nil{return w.failed}
    lane:=w.lanes[f]
    // P5 keeps preparing while this family's P6 SQL writer is active.
    // Preserve the four-buffer cap, but wait for ONLY the oldest commit
    // when full. Draining all four here caused recurrent SQL writer gaps.
    if len(lane.outstanding)>=privateC1MaxFamilyHandoffsInFlight {
        started:=time.Now()
        lane.backpressureWaits++
        err:=w.waitNextFamily(ctx,f)
        lane.backpressureWaitWall+=time.Since(started)
        if err!=nil{return err}
    }
    if w.sourceLast==nil{return errors.New("FI C1: family has no ordered source-parent fence")}
    job:=privateC1SQLJob{rows:rows,source:w.sourceLast,done:make(chan error,1)}
    select{
    case <-ctx.Done():return ctx.Err()
    case <-w.ctx.Done():return w.ctx.Err()
    case lane.jobs<-job:
    }
    lane.outstanding=append(lane.outstanding,job.done)
    return nil
}

// The signed reader owns the outstanding FIFO. An ACK is retired only
// after its SQL transaction completes. This is the same FIFO used for
// File-before-USN dependency fences and for C1's final five-family gate.
func(w *privateC1FiveSQL) waitNextFamily(ctx context.Context,f privateP6Family)error{
    if w==nil||ctx==nil||w.ctx==nil||f>=privateP6FamilyCount||w.lanes[f]==nil{
        return errors.New("FI C1: invalid oldest SQL family acknowledgment")
    }
    lane:=w.lanes[f]
    if len(lane.outstanding)==0{return nil}
    ack:=lane.outstanding[0]
    select{
    case <-ctx.Done():return ctx.Err()
    case <-w.ctx.Done():return w.ctx.Err()
    case err,ok:=<-ack:
        // Retire only the acknowledged handoff. Other completed or
        // in-progress SQL jobs remain queued, maintaining continuity.
        lane.outstanding[0]=nil
        lane.outstanding=lane.outstanding[1:]
        if !ok&&err==nil{err=errors.New("missing SQL writer acknowledgment")}
        if err!=nil{
            w.failed=fmt.Errorf("FI C1: family %s SQL commit: %w",privateP6FamilyNames[f],err)
            return w.failed
        }
        return nil
    }
}

func(w *privateC1FiveSQL) WaitFamily(ctx context.Context,f privateP6Family)error{
    if w==nil||ctx==nil||f>=privateP6FamilyCount||w.lanes[f]==nil{
        return errors.New("FI C1: invalid SQL family barrier")
    }
    for len(w.lanes[f].outstanding)>0{
        if err:=w.waitNextFamily(ctx,f);err!=nil{return err}
    }
    return nil
}
func(w *privateC1FiveSQL) WaitAll(ctx context.Context)error{
    if w==nil{return errors.New("FI C1: missing five SQL lanes")}
    // Ensure every source parent is durable before the final typed marker.
    // Already-running family connections can still process earlier parents.
    joined:=w.WaitSource(ctx)
    // All 5 can run concurrently; wait only after all family buffers
    // have handed off their final batches.
    for f:=privateP6Family(0);f<privateP6FamilyCount;f++{
        joined=errors.Join(joined,w.WaitFamily(ctx,f))
    }
    if joined!=nil{return joined}
    var total int64
    for _,lane:=range w.lanes{total+=lane.committed}
    if total!=w.parentRows {
        return fmt.Errorf("FI C1: five committed child counts %d differ from P6 signed parent count %d",total,w.parentRows)
    }
    return nil
}
func(w *privateC1FiveSQL) Stats()(int64,int64,[privateP6FamilyCount]int64){
    var family [privateP6FamilyCount]int64
    if w==nil{return 0,0,family}
    var total int64
    for i,lane:=range w.lanes{
        family[i]=lane.committed
        total+=family[i]
    }
    fmt.Printf("FI C1 SQL PROFILE family=SourceParent rows=%d handoffs=%d sql_wall=%s\n",
        w.parentRows,w.parentHandoffs,w.parentSQLWall)
    fmt.Printf("FI C1 ORDERED SOURCE BACKPRESSURE max_outstanding=%d waits=%d wall=%s remaining_ack=%d\n",
        privateC1MaxFamilyHandoffsInFlight,w.sourceBackpressureWaits,
        w.sourceBackpressureWall,len(w.sourceOutstanding))
    for _,lane:=range w.lanes{
        fmt.Printf("FI C1 SQL PROFILE family=%s rows=%d handoffs=%d sql_wall=%s parent_wait=%s fk_lookup=%s projector=%s commit=%s\n",
            privateP6FamilyNames[lane.family],lane.committed,lane.handoffs,lane.sqlWall,
            lane.sourceParentWaitWall,lane.identityLookup,lane.projectionWall,lane.commitWall)
        fmt.Printf("FI C1 P6 CONTINUOUS FAMILY family=%s max_outstanding=%d backpressure_waits=%d backpressure_wall=%s remaining_ack=%d\n",
            privateP6FamilyNames[lane.family],privateC1MaxFamilyHandoffsInFlight,
            lane.backpressureWaits,lane.backpressureWaitWall,len(lane.outstanding))
    }
    // Security's 285s projector wall is already known. Break it into
    // original P6 event/scope/field COPY timing and unchanged child setup.
    // Per-stage durations are cumulative and may be nested; do not add
    // them to the C1 overall wall clock or parallel family timings.
    s:=w.lanes[privateP6Security].securityCopies
    fmt.Printf("FI C1 SECURITY COPY PROFILE batches=%d events=%d scopes=%d fields=%d source_bytes=%d source_copy=%s event_copy=%s scope_copy=%s field_copy=%s child_prepare=%s bulk_id_lookup=%s bulk_prepare=%s\n",
        s.Batches,s.Events,s.Scopes,s.Fields,s.SourceBytes,
        s.SourceCopy,s.EventCopy,s.ScopeCopy,s.FieldCopy,
        s.ChildPrepare,s.IDLookup,s.Prepare)
    return w.parentRows,total,family
}
func(w *privateC1FiveSQL) Close(){
    if w==nil||w.closed{return}
    w.closed=true
    if w.sourceJobs!=nil {close(w.sourceJobs)}
    for _,lane:=range w.lanes {
        if lane!=nil {close(lane.jobs)}
    }
    // Family workers may be awaiting a source commit, so join its writer
    // first. Never close the parent connection while COPY is active.
    w.sourceWG.Wait()
    w.wg.Wait()
    w.cancel()
    for _,lane:=range w.lanes{
        if lane!=nil&&lane.conn!=nil {_=lane.conn.Close(context.Background())}
    }
    if w.parent!=nil {_=w.parent.Close(context.Background())}
}
var _ privateP6SQLHandoff=(*privateC1FiveSQL)(nil)
