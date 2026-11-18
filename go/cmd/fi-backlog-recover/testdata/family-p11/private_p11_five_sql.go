// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// P11 ISOLATED C220 CLONE: P6 native source/relational SQL, six real backend
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

type privateP11SQLJob struct {
    rows []privateP6Record
    done chan error
}
type privateP11SQLLane struct {
    family privateP6Family
    module privateP11FamilyModule
    conn *pgx.Conn
    jobs chan privateP11SQLJob
    outstanding []chan error // owner: canonical reader goroutine only
    committed int64
    handoffs int64
    err error
    sqlWall time.Duration
    identityLookup time.Duration
    projectionWall time.Duration
    commitWall time.Duration
    // Only this lane goroutine writes these original SecurityBulk counters.
    // They are aggregates of P6's existing projector/COPY measurements;
    // no extra SQL, source staging, or per-row timer is introduced.
    securityCopies securityBulkTimingCounters
}
type privateP11FiveSQL struct {
    parent *pgx.Conn
    lanes [privateP6FamilyCount]*privateP11SQLLane
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

func privateP11Enabled() bool {
    return os.Getenv("FI_W512_P11_P6_DIRECT")=="1" &&
        os.Getenv("FI_W512_P7_SQL_WRITERS")=="" &&
        os.Getenv("FI_W512_P8_REUSE")=="" &&
        os.Getenv("FI_W512_P9_DIRECT_STREAM")=="" &&
        privateP6Selected()
}

func privateP11CloneConnection(ctx context.Context,dsn,expectedPGDATA string)(*pgx.Conn,int64,error){
    if dsn==""||expectedPGDATA==""||
        !strings.HasPrefix(expectedPGDATA,"/home/jwood/fi-window-bench-w512-family-p3-")||
        !strings.HasSuffix(expectedPGDATA,"/clone-w512-2g/data") ||
        !strings.Contains(dsn,"sslmode=disable")||
        !strings.Contains(dsn,"user=fi_ingest") ||
        !strings.Contains(dsn,"host=/var/tmp/fi-window-chunks-family-p3-") {
        return nil,0,errors.New("FI P11: exact private C220 clone DSN/PGDATA required")
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
        return nil,0,fmt.Errorf("FI P11: unexpected clone session role=%q standby=%v pid=%d err=%v",user,recovery,pid,err)
    }
    return conn,pid,nil
}

func newPrivateP11FiveSQL(ctx context.Context,dsn,pgdata,sourceID string)(*privateP11FiveSQL,error){
    if !privateP11Enabled()||ctx==nil||sourceID==""{
        return nil,errors.New("FI P11: private P6 five-writer feature not selected")
    }
    owner,cancel:=context.WithCancel(ctx)
    w:=&privateP11FiveSQL{ctx:owner,cancel:cancel,sourceID:sourceID}
    cleanup:=func(){
        cancel()
        if w.parent!=nil { _=w.parent.Close(context.Background()) }
        for _,lane:=range w.lanes {
            if lane!=nil&&lane.conn!=nil {_=lane.conn.Close(context.Background())}
        }
    }
    parent,parentPID,err:=privateP11CloneConnection(ctx,dsn,pgdata)
    if err!=nil{cleanup();return nil,err}
    w.parent=parent
    pids:=map[int64]bool{parentPID:true}
    for i:=range w.lanes{
        conn,pid,e:=privateP11CloneConnection(ctx,dsn,pgdata)
        if e!=nil{cleanup();return nil,e}
        if pids[pid]{
            conn.Close(context.Background());cleanup()
            return nil,errors.New("FI P11: duplicate backend PID, five independent connections required")
        }
        pids[pid]=true
        w.lanes[i]=&privateP11SQLLane{family:privateP6Family(i),
            module:privateP11SQLModules[i],
            conn:conn,jobs:make(chan privateP11SQLJob,2)}
    }
    // Only after every connection is verified do SQL goroutines begin.
    for _,lane:=range w.lanes{
        w.wg.Add(1)
        go w.runLane(lane)
    }
    fmt.Printf("FI P11 P6 NATIVE SQL BACKENDS parent=1 family_writers=5 distinct_pids=%d clone_only=true\n",len(pids))
    return w,nil
}

func(w *privateP11FiveSQL) runLane(lane *privateP11SQLLane){
    defer w.wg.Done()
    for job:=range lane.jobs {
        started:=time.Now()
        err:=w.writeFamily(w.ctx,lane,job.rows)
        lane.sqlWall+=time.Since(started)
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
// caches before invoking any child projector. Each concurrent P11 family
// transaction needs its own copies: never share a mutable COPY buffer across
// five SQL writers, and NEVER enable SendBatch on privateProjectionTx.
func privateP11BoundedProjectorContext(ctx context.Context)(
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

func(w *privateP11FiveSQL) writeFamily(ctx context.Context,lane *privateP11SQLLane,rows []privateP6Record)error{
    if lane.err!=nil{return lane.err}
    if err:=ctx.Err();err!=nil{return err}
    tx,err:=lane.conn.Begin(ctx)
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    profile:=&ingestStageProfile{}
    coordinator,err:=newPrivateP6SQLCoordinator(privateProjectionTx{Tx:tx},
        w.sourceID,profile)
    if err!=nil{return err}
    writeCtx,hashCopy,aceCopy,usnCopy:=privateP11BoundedProjectorContext(ctx)
    if lane.family==privateP6Security {
        // P12 is opt-in only through this isolated experiment's Security lane.
        // Other four families and original P3/P1 limits remain unchanged.
        writeCtx=privateP12SecurityFieldEnvelopeContext(writeCtx)
    }
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
        s.FieldLatency.Calls+=counters.FieldLatency.Calls
        s.FieldLatency.AtLeastOneSecond+=counters.FieldLatency.AtLeastOneSecond
        s.FieldLatency.AtLeastFiveSeconds+=counters.FieldLatency.AtLeastFiveSeconds
        if counters.FieldLatency.Calls>0{
            if s.FieldLatency.Calls==counters.FieldLatency.Calls ||
                counters.FieldLatency.Min<s.FieldLatency.Min{
                s.FieldLatency.Min=counters.FieldLatency.Min
            }
            if counters.FieldLatency.Max>s.FieldLatency.Max{
                s.FieldLatency.Max=counters.FieldLatency.Max
            }
        }
    }
    // The same privateProjectionTx rewrites all five family's COPY
    // targets into fi_recovery_projection. Drain *before* SQL COMMIT:
    // pending hashes/ACEs/USN changes and reasons are real FK children.
    projector:=privateProjectionTx{Tx:tx}
    if err=usnCopy.flushAll(writeCtx,projector);err!=nil{
        return fmt.Errorf("FI P11: USN/reason child COPY: %w",err)
    }
    if err=hashCopy.flush(writeCtx,projector);err!=nil{
        return fmt.Errorf("FI P11: content-hash child COPY: %w",err)
    }
    if err=aceCopy.flushAll(writeCtx,projector);err!=nil{
        return fmt.Errorf("FI P11: DACL/SACL child COPY: %w",err)
    }
    startedCommit:=time.Now()
    err=tx.Commit(ctx)
    lane.commitWall+=time.Since(startedCommit)
    return err
}

func(w *privateP11FiveSQL) Source(ctx context.Context,rows []privateP6Record)error{
    if w==nil||w.closed||len(rows)==0{return errors.New("FI P11: invalid source parent handoff")}
    if w.failed!=nil{return w.failed}
    startedSource:=time.Now()
    tx,err:=w.parent.Begin(ctx)
    if err!=nil{w.failed=err;return err}
    defer tx.Rollback(context.Background())
    coordinator,err:=newPrivateP6SQLCoordinator(privateProjectionTx{Tx:tx},
        w.sourceID,&ingestStageProfile{})
    if err==nil{err=coordinator.Source(ctx,rows)}
    if err==nil{err=tx.Commit(ctx)}
    if err!=nil{
        w.failed=fmt.Errorf("FI P11: ordered P6 source parent failed: %w",err)
        return w.failed
    }
    w.parentRows+=int64(len(rows))
    w.parentHandoffs++
    w.parentSQLWall+=time.Since(startedSource)
    return nil
}

func(w *privateP11FiveSQL) Family(ctx context.Context,f privateP6Family,rows []privateP6Record)error{
    if w==nil||w.closed||f>=privateP6FamilyCount||len(rows)==0{
        return errors.New("FI P11: invalid P6 family handoff")
    }
    if w.failed!=nil{return w.failed}
    lane:=w.lanes[f]
    // At most 4 pending handed-off buffers per family; each is itself
    // bounded by the original P6 row/byte capacity. Do not grow an
    // unlimited backlog waiting for a slow SQL family.
    if len(lane.outstanding)>=4 {
        if err:=w.WaitFamily(ctx,f);err!=nil{return err}
    }
    job:=privateP11SQLJob{rows:rows,done:make(chan error,1)}
    select{
    case <-ctx.Done():return ctx.Err()
    case <-w.ctx.Done():return w.ctx.Err()
    case lane.jobs<-job:
    }
    lane.outstanding=append(lane.outstanding,job.done)
    return nil
}

func(w *privateP11FiveSQL) WaitFamily(ctx context.Context,f privateP6Family)error{
    if w==nil||f>=privateP6FamilyCount{return errors.New("FI P11: invalid SQL family barrier")}
    lane:=w.lanes[f]
    pending:=lane.outstanding
    lane.outstanding=nil
    for _,ack:=range pending {
        select{
        case <-ctx.Done():return ctx.Err()
        case err:=<-ack:
            if err!=nil{
                w.failed=fmt.Errorf("FI P11: family %s SQL commit: %w",privateP6FamilyNames[f],err)
                return w.failed
            }
        }
    }
    return nil
}
func(w *privateP11FiveSQL) WaitAll(ctx context.Context)error{
    if w==nil{return errors.New("FI P11: missing five SQL lanes")}
    var joined error
    // All 5 can run concurrently; wait only after all family buffers
    // have handed off their final batches.
    for f:=privateP6Family(0);f<privateP6FamilyCount;f++{
        joined=errors.Join(joined,w.WaitFamily(ctx,f))
    }
    if joined!=nil{return joined}
    var total int64
    for _,lane:=range w.lanes{total+=lane.committed}
    if total!=w.parentRows {
        return fmt.Errorf("FI P11: five committed child counts %d differ from P6 signed parent count %d",total,w.parentRows)
    }
    return nil
}
func(w *privateP11FiveSQL) Stats()(int64,int64,[privateP6FamilyCount]int64){
    var family [privateP6FamilyCount]int64
    if w==nil{return 0,0,family}
    var total int64
    for i,lane:=range w.lanes{
        family[i]=lane.committed
        total+=family[i]
    }
    fmt.Printf("FI P11 SQL PROFILE family=SourceParent rows=%d handoffs=%d sql_wall=%s\n",
        w.parentRows,w.parentHandoffs,w.parentSQLWall)
    for _,lane:=range w.lanes{
        fmt.Printf("FI P11 SQL PROFILE family=%s rows=%d handoffs=%d sql_wall=%s fk_lookup=%s projector=%s commit=%s\n",
            privateP6FamilyNames[lane.family],lane.committed,lane.handoffs,lane.sqlWall,
            lane.identityLookup,lane.projectionWall,lane.commitWall)
    }
    // Security's 285s projector wall is already known. Break it into
    // original P6 event/scope/field COPY timing and unchanged child setup.
    // Per-stage durations are cumulative and may be nested; do not add
    // them to the P11 overall wall clock or parallel family timings.
    s:=w.lanes[privateP6Security].securityCopies
    avg:=time.Duration(0)
    if s.FieldLatency.Calls>0{avg=s.FieldCopy/time.Duration(s.FieldLatency.Calls)}
    fmt.Printf("FI P11 SECURITY COPY PROFILE batches=%d events=%d scopes=%d fields=%d source_bytes=%d source_copy=%s event_copy=%s scope_copy=%s field_copy=%s child_prepare=%s bulk_id_lookup=%s bulk_prepare=%s field_calls=%d field_avg=%s field_min=%s field_max=%s ge_1s=%d ge_5s=%d\n",
        s.Batches,s.Events,s.Scopes,s.Fields,s.SourceBytes,
        s.SourceCopy,s.EventCopy,s.ScopeCopy,s.FieldCopy,
        s.ChildPrepare,s.IDLookup,s.Prepare,
        s.FieldLatency.Calls,avg,s.FieldLatency.Min,s.FieldLatency.Max,
        s.FieldLatency.AtLeastOneSecond,s.FieldLatency.AtLeastFiveSeconds)
    fmt.Printf("FI P12 SECURITY FIELD ENVELOPE effective_rows=65536 effective_bytes=16777216 original_p3_rows=32768 original_p3_bytes=8388608 family=Security clone_only=true\n")
    return w.parentRows,total,family
}
func(w *privateP11FiveSQL) Close(){
    if w==nil||w.closed{return}
    w.closed=true
    for _,lane:=range w.lanes {
        if lane!=nil {close(lane.jobs)}
    }
    w.wg.Wait()
    w.cancel()
    for _,lane:=range w.lanes{
        if lane!=nil&&lane.conn!=nil {_=lane.conn.Close(context.Background())}
    }
    if w.parent!=nil {_=w.parent.Close(context.Background())}
}
var _ privateP6SQLHandoff=(*privateP11FiveSQL)(nil)
