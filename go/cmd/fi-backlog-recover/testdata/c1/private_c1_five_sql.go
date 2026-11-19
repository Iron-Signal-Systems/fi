// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 ISOLATED C220 CLONE: P6 native source/relational SQL, one ordered source-parent SQL connection and an adaptive shared pool
// of 1..16 SQL workers. Five P5/P6 families remain independent.
// No new pending_source_record staging, no P7 preparer bridge, no alternate
// relational projectors. Failure renders this disposable SQL clone unusable;
// never resume it or treat partially committed parents as a checkpoint.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "os"
    "strconv"
    "strings"
    "sync"
    "time"

    "github.com/jackc/pgx/v5"
)

// Source-parent handoffs remain bounded to four. Family SQL admission is
// independently bounded to at least four and at most the configured pool max.
const privateC1MaxFamilyHandoffsInFlight = 4
const privateC1DefaultSQLWorkersMax = 5
const privateC1HardSQLWorkersMax = 16
const privateC1SQLWorkerIdleRetire = 30 * time.Second

// Parent ACKs are broadcast fences: multiple child transactions can depend
// on the same committed source prefix without stealing an acknowledgment.
type privateC1SourceAck struct {
    done chan struct{}
    err error
}
type privateC1SourceJob struct {
    rows []privateP6Record
    ack *privateC1SourceAck
}
type privateC1SQLJob struct {
    family privateP6Family
    rows []privateP6Record
    source *privateC1SourceAck
    done chan error
}
type privateC1SQLLane struct {
    family privateP6Family
    module privateC1FamilyModule
    mu sync.Mutex // SQL metrics and first SQL error; workers are interchangeable
    outstanding []chan error // signed reader only
    committed int64
    handoffs int64
    err error
    sqlWall time.Duration
    sourceParentWaitWall time.Duration
    identityLookup time.Duration
    projectionWall time.Duration
    commitWall time.Duration
    backpressureWaits int64 // signed reader only
    backpressureWaitWall time.Duration
    securityCopies securityBulkTimingCounters
}
type privateC1FiveSQL struct {
    parent *pgx.Conn
    sourceJobs chan privateC1SourceJob
    sourceOutstanding []*privateC1SourceAck // signed reader only
    sourceLast *privateC1SourceAck
    sourceWG sync.WaitGroup
    sourceBackpressureWaits int64
    sourceBackpressureWall time.Duration
    lanes [privateP6FamilyCount]*privateC1SQLLane
    jobs chan privateC1SQLJob // ONE shared ready queue; no family owns a SQL worker
    dsn,pgdata string
    maxWorkers int
    mu sync.Mutex
    workerCount int
    busyWorkers int
    activeSecuritySQL int
    peakSecuritySQL int
    completedJobs int64
    peakWorkers int
    scaleUps int
    scaleDowns int
    pids map[int64]bool // live PostgreSQL connections, including ordered parent
    sourceID string
    ctx context.Context
    cancel context.CancelFunc
    wg sync.WaitGroup
    parentRows int64
    parentHandoffs int64
    parentSQLWall time.Duration
    closed bool
    failed error // signed reader only
}

// The C220 test setting mirrors the fi-backend runtime configuration.
func privateC1SQLWorkersMax() (int,error) {
    raw:=os.Getenv("FI_W512_C1_SQL_WORKERS_MAX")
    if raw=="" {return privateC1DefaultSQLWorkersMax,nil}
    n,e:=strconv.Atoi(raw)
    if e!=nil||n<1||n>privateC1HardSQLWorkersMax{
        return 0,fmt.Errorf("FI C1: SQL worker maximum must be between 1 and 16, got %q",raw)
    }
    return n,nil
}
func (w *privateC1FiveSQL) familyLimit() int {
    if w==nil||w.maxWorkers<privateC1MaxFamilyHandoffsInFlight {
        return privateC1MaxFamilyHandoffsInFlight
    }
    return w.maxWorkers
}
// The P6 USN projector binds each object to a preceding capture boundary
// using signed source-record order and a generation-local capture map.
// Unrelated SQL families can run concurrently, but a later USN handoff
// must not begin SQL before the prior USN handoff COMMITTED. A single
// outstanding USN handoff preserves this without weakening capture checks.
func (w *privateC1FiveSQL) familyHandoffLimit(f privateP6Family) int {
    if f==privateP6USN {
        return 1
    }
    return w.familyLimit()
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
        return nil,errors.New("FI C1: private P6 shared SQL worker pool not selected")
    }
    max,e:=privateC1SQLWorkersMax()
    if e!=nil{return nil,e}
    owner,cancel:=context.WithCancel(ctx)
    w:=&privateC1FiveSQL{
        ctx:owner,cancel:cancel,sourceID:sourceID,dsn:dsn,pgdata:pgdata,
        maxWorkers:max,sourceJobs:make(chan privateC1SourceJob,2),
        jobs:make(chan privateC1SQLJob,max*2),pids:make(map[int64]bool),
    }
    parent,pid,e:=privateC1CloneConnection(ctx,dsn,pgdata)
    if e!=nil{cancel();return nil,e}
    w.parent=parent
    w.pids[pid]=true
    for i:=range w.lanes{
        w.lanes[i]=&privateC1SQLLane{
            family:privateP6Family(i),module:privateC1SQLModules[i],
        }
    }
    // Start one real verified SQL connection; remaining connections are
    // created only when ready family buffers exceed idle worker capacity.
    if e=w.startWorker(ctx);e!=nil{
        cancel()
        _=parent.Close(context.Background())
        return nil,e
    }
    w.sourceWG.Add(1)
    go w.runSource()
    fmt.Printf("FI C1 P6 NATIVE SQL BACKENDS parent=1 shared_workers_initial=1 workers_max=%d distinct_pids=2 clone_only=true\n",max)
    return w,nil
}

// Called from the signed-reader goroutine to add ONE verified PostgreSQL
// session. Workers are never pinned to Security, File, Coverage, USN or Other.
func (w *privateC1FiveSQL) startWorker(ctx context.Context)error{
    conn,pid,err:=privateC1CloneConnection(ctx,w.dsn,w.pgdata)
    if err!=nil{return fmt.Errorf("FI C1: shared SQL worker connection: %w",err)}
    w.mu.Lock()
    if w.pids[pid]||w.workerCount>=w.maxWorkers{
        w.mu.Unlock()
        _=conn.Close(context.Background())
        return errors.New("FI C1: duplicate backend PID or SQL worker cap exceeded")
    }
    w.pids[pid]=true
    w.workerCount++
    if w.workerCount>w.peakWorkers{w.peakWorkers=w.workerCount}
    if w.peakWorkers>1{w.scaleUps++}
    w.wg.Add(1)
    w.mu.Unlock()
    go w.runWorker(conn,pid)
    return nil
}

// Scale up if queued buffers exceed the currently idle SQL workers. Idle
// connections retire after 30 seconds, never below one live worker.
func (w *privateC1FiveSQL) growWorkers(ctx context.Context)error{
    for {
        w.mu.Lock()
        needed:=len(w.jobs)-(w.workerCount-w.busyWorkers)
        room:=w.workerCount<w.maxWorkers
        w.mu.Unlock()
        if !room||needed<=0{return nil}
        if err:=w.startWorker(ctx);err!=nil{return err}
    }
}
func (w *privateC1FiveSQL) runWorker(conn *pgx.Conn,pid int64){
    retired:=false
    defer func(){
        _=conn.Close(context.Background())
        w.mu.Lock()
        if !retired{w.workerCount--}
        delete(w.pids,pid)
        w.mu.Unlock()
        w.wg.Done()
    }()
    timer:=time.NewTimer(privateC1SQLWorkerIdleRetire)
    defer timer.Stop()
    for {
        select {
        case job,ok:=<-w.jobs:
            if !ok{return}
            w.mu.Lock()
            w.busyWorkers++
            w.mu.Unlock()
            lane:=w.lanes[job.family]
            parentStarted:=time.Now()
            err:=privateC1AwaitSource(w.ctx,job.source)
            parentWait:=time.Since(parentStarted)
            var sqlWall time.Duration
            if err==nil{
                if job.family==privateP6Security{
                    w.mu.Lock()
                    w.activeSecuritySQL++
                    if w.activeSecuritySQL>w.peakSecuritySQL{
                        w.peakSecuritySQL=w.activeSecuritySQL
                    }
                    w.mu.Unlock()
                }
                sqlStarted:=time.Now()
                err=w.writeFamily(w.ctx,lane,conn,job.rows)
                sqlWall=time.Since(sqlStarted)
                if job.family==privateP6Security{
                    w.mu.Lock()
                    w.activeSecuritySQL--
                    w.mu.Unlock()
                }
            }
            lane.mu.Lock()
            lane.sourceParentWaitWall+=parentWait
            lane.sqlWall+=sqlWall
            if err==nil{
                lane.committed+=int64(len(job.rows))
                lane.handoffs++
            }else if lane.err==nil{
                lane.err=err
            }
            lane.mu.Unlock()
            w.mu.Lock()
            w.busyWorkers--
            w.completedJobs++
            w.mu.Unlock()
            job.done<-err
            close(job.done)
            if !timer.Stop(){select{case <-timer.C:default:}}
            timer.Reset(privateC1SQLWorkerIdleRetire)
        case <-timer.C:
            w.mu.Lock()
            if w.workerCount>1&&len(w.jobs)==0{
                w.workerCount--
                w.scaleDowns++
                retired=true
                w.mu.Unlock()
                return
            }
            w.mu.Unlock()
            timer.Reset(privateC1SQLWorkerIdleRetire)
        }
    }
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

func(w *privateC1FiveSQL) writeFamily(ctx context.Context,lane *privateC1SQLLane,conn *pgx.Conn,rows []privateP6Record)error{
    lane.mu.Lock()
    previous:=lane.err
    lane.mu.Unlock()
    if previous!=nil{return previous}
    if err:=ctx.Err();err!=nil{return err}
    tx,err:=conn.Begin(ctx)
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
    lane.mu.Lock()
    lane.identityLookup+=lookupTime
    lane.projectionWall+=projectTime
    lane.mu.Unlock()
    if e!=nil{return e}
    if lane.family==privateP6Security {
        // The original P6 projector already populated this per-handoff
        // profile. Accumulate those counters before it goes out of scope.
        // No instrumentation is placed inside event or field COPY loops.
        counters:=profile.SecurityBulk
        lane.mu.Lock()
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
        lane.mu.Unlock()
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
    lane.mu.Lock()
    lane.commitWall+=time.Since(startedCommit)
    lane.mu.Unlock()
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
    if w==nil||w.closed||f>=privateP6FamilyCount||len(rows)==0||w.jobs==nil{
        return errors.New("FI C1: invalid shared SQL family handoff")
    }
    if w.failed!=nil{return w.failed}
    lane:=w.lanes[f]
    if len(lane.outstanding)>=w.familyHandoffLimit(f){
        started:=time.Now()
        lane.backpressureWaits++
        err:=w.waitNextFamily(ctx,f)
        lane.backpressureWaitWall+=time.Since(started)
        if err!=nil{return err}
    }
    if w.sourceLast==nil{return errors.New("FI C1: family has no ordered source-parent fence")}
    job:=privateC1SQLJob{family:f,rows:rows,source:w.sourceLast,done:make(chan error,1)}
    select{
    case <-ctx.Done():return ctx.Err()
    case <-w.ctx.Done():return w.ctx.Err()
    case w.jobs<-job:
    }
    lane.outstanding=append(lane.outstanding,job.done)
    if err:=w.growWorkers(ctx);err!=nil{
        w.failed=fmt.Errorf("FI C1: adaptive SQL pool could not scale: %w",err)
        return w.failed
    }
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
    for _,lane:=range w.lanes{
        lane.mu.Lock()
        total+=lane.committed
        lane.mu.Unlock()
    }
    if total!=w.parentRows {
        return fmt.Errorf("FI C1: shared pool committed child count %d differs from signed parent count %d",total,w.parentRows)
    }
    return nil
}
func(w *privateC1FiveSQL) Stats()(int64,int64,[privateP6FamilyCount]int64){
    var family [privateP6FamilyCount]int64
    if w==nil{return 0,0,family}
    var total int64
    fmt.Printf("FI C1 SQL PROFILE family=SourceParent rows=%d handoffs=%d sql_wall=%s\n",
        w.parentRows,w.parentHandoffs,w.parentSQLWall)
    fmt.Printf("FI C1 ORDERED SOURCE BACKPRESSURE max_outstanding=%d waits=%d wall=%s remaining_ack=%d\n",
        privateC1MaxFamilyHandoffsInFlight,w.sourceBackpressureWaits,
        w.sourceBackpressureWall,len(w.sourceOutstanding))
    for _,lane:=range w.lanes{
        lane.mu.Lock()
        family[lane.family]=lane.committed
        total+=lane.committed
        fmt.Printf("FI C1 SQL PROFILE family=%s rows=%d handoffs=%d sql_wall=%s parent_wait=%s fk_lookup=%s projector=%s commit=%s\n",
            privateP6FamilyNames[lane.family],lane.committed,lane.handoffs,lane.sqlWall,
            lane.sourceParentWaitWall,lane.identityLookup,lane.projectionWall,lane.commitWall)
        lane.mu.Unlock()
        fmt.Printf("FI C1 P6 CONTINUOUS FAMILY family=%s max_outstanding=%d backpressure_waits=%d backpressure_wall=%s remaining_ack=%d\n",
            privateP6FamilyNames[lane.family],w.familyLimit(),
            lane.backpressureWaits,lane.backpressureWaitWall,len(lane.outstanding))
    }
    s:=w.lanes[privateP6Security].securityCopies
    fmt.Printf("FI C1 SECURITY COPY PROFILE batches=%d events=%d scopes=%d fields=%d source_bytes=%d source_copy=%s event_copy=%s scope_copy=%s field_copy=%s child_prepare=%s bulk_id_lookup=%s bulk_prepare=%s\n",
        s.Batches,s.Events,s.Scopes,s.Fields,s.SourceBytes,
        s.SourceCopy,s.EventCopy,s.ScopeCopy,s.FieldCopy,
        s.ChildPrepare,s.IDLookup,s.Prepare)
    w.mu.Lock()
    fmt.Printf("FI C1 SHARED SQL POOL workers_min=1 workers_max=%d workers_peak=%d workers_current=%d busy=%d scale_ups=%d scale_downs=%d available_connections=%d security_sql_peak=%d jobs_completed=%d\n",
        w.maxWorkers,w.peakWorkers,w.workerCount,w.busyWorkers,
        w.scaleUps,w.scaleDowns,len(w.pids)-1,w.peakSecuritySQL,w.completedJobs)
    w.mu.Unlock()
    return w.parentRows,total,family
}

func(w *privateC1FiveSQL) Close(){
    if w==nil||w.closed{return}
    w.closed=true
    if w.sourceJobs!=nil {close(w.sourceJobs)}
    if w.jobs!=nil {close(w.jobs)}
    // No family job can be lost: the shared workers drain the closed queue,
    // including their source-parent fences, before PostgreSQL is closed.
    w.sourceWG.Wait()
    w.wg.Wait()
    w.cancel()
    if w.parent!=nil {_=w.parent.Close(context.Background())}
}

var _ privateP6SQLHandoff=(*privateC1FiveSQL)(nil)
