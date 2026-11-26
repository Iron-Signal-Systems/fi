//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 ISOLATED C220 CLONE: P6 native source/relational SQL, one ordered source-parent SQL connection and an adaptive shared pool
// of 1..32 SQL workers. Five P5/P6 families remain independent.
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
const privateC1HardSQLWorkersMax = 32
const privateC1SQLWorkerIdleRetire = 30 * time.Second
// USN SQL is still strictly serial, but its admission is asynchronous.
// Each retained buffer obeys the existing per-family limits (including the
// governed oversize-single-record exception). The queue cannot grow without
// bound; it creates no extra PostgreSQL connections or SQL workers.
const privateC1MaxPendingUSNHandoffs = 64

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
    // The dispatcher's read-only broadcast fences do not steal the
    // signed reader's SQL result from done.
    committed *privateC1SourceAck
    filePrerequisites []*privateC1SourceAck
}
type privateC1SQLLane struct {
    family privateP6Family
    module privateC1FamilyModule
    mu sync.Mutex // SQL metrics and first SQL error; workers are interchangeable
    outstanding []chan error // signed reader only
    fileReceipts []*privateC1SourceAck // File only; tracks same FIFO, signed-reader owned
    latestCommitted *privateC1SourceAck // independent network ACK observes this broadcast fence
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
    // The original private clone keeps its exact socket/PGDATA guard;
    // fi-sor uses a separate fail-closed LOCAL PostgreSQL opener. Both
    // execute this same verified C1 source and five-family SQL engine.
    openSQL func(context.Context,string,string)(*pgx.Conn,int64,error)
    cloneOnly bool
    projectionSchema string // exact authorized destination for all P6 SQL/COPY
    parent *pgx.Conn
    sourceProfile bool // explicit 8GiB-only profiling, never a production setting
    parentBackendPID int64
    parentPreCopyWall time.Duration
    parentCursorNextWall time.Duration
    parentCursorValuesWall time.Duration
    parentCOPYRemainderWall time.Duration
    parentProfiledCopyCalls int64
    parentProfiledValues int64
    commitReady *privateC1CommitReady // immutable attachment before any source/family job
    sourceJobs chan privateC1SourceJob
    sourceOutstanding []*privateC1SourceAck // signed reader only
    sourceLast *privateC1SourceAck
    sourceWG sync.WaitGroup
    sourceBackpressureWaits int64
    sourceBackpressureWall time.Duration
    lanes [privateP6FamilyCount]*privateC1SQLLane
    jobs chan privateC1SQLJob // ONE shared ready queue; no family owns a SQL worker
    usnPending chan privateC1SQLJob // bounded, ordered, no dedicated SQL connection
    usnWG sync.WaitGroup
    usnPeakOutstanding int // signed-reader owned
    usnFileWaitWall time.Duration // dispatcher writes, mu protects reads
    usnSQLWaitWall time.Duration // dispatcher writes, mu protects reads
    usnCompleted int64 // dispatcher writes, mu protects reads
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
    // Only the authenticated fi-sor Bootstrap binds this immutable signed
    // generation identity. Every USN SQL handoff creates a fresh bounded
    // capture state and restores prior committed boundaries from Pending SQL.
    // Never share a mutable USN capture map between SQL transactions.
    usnGenerationID string
    ctx context.Context
    cancel context.CancelFunc
    wg sync.WaitGroup
    parentRows int64
    parentHandoffs int64
    parentSQLWall time.Duration
    parentBeginWall time.Duration
    parentCopyWall time.Duration
    parentCommitWall time.Duration
    parentReadinessWall time.Duration
    closed bool
    failed error // signed reader only
}

// The C220 test setting mirrors the fi-backend runtime configuration.
func privateC1SQLWorkersMax() (int,error) {
    raw:=os.Getenv("FI_W512_C1_SQL_WORKERS_MAX")
    if raw=="" {return privateC1DefaultSQLWorkersMax,nil}
    n,e:=strconv.Atoi(raw)
    if e!=nil||n<1||n>privateC1HardSQLWorkersMax{
        return 0,fmt.Errorf("FI C1: SQL worker maximum must be between 1 and 32, got %q",raw)
    }
    return n,nil
}
func (w *privateC1FiveSQL) familyLimit() int {
    if w==nil||w.maxWorkers<privateC1MaxFamilyHandoffsInFlight {
        return privateC1MaxFamilyHandoffsInFlight
    }
    return w.maxWorkers
}
// USN admission is buffered independently of USN execution. The dispatcher
// submits only one USN job at a time to the SAME shared SQL worker pool,
// and waits for that transaction to commit before submitting its successor.
// The 64-slot bound applies backpressure only when genuinely saturated.
func (w *privateC1FiveSQL) familyHandoffLimit(f privateP6Family) int {
    if f==privateP6USN {
        return privateC1MaxPendingUSNHandoffs
    }
    return w.familyLimit()
}
// Family buffers may defer File commit fencing to the ordered USN dispatcher.
// Other SQL sinks preserve the original synchronous behavior.
func (w *privateC1FiveSQL) AsyncUSNDependencies() bool { return w!=nil&&w.usnPending!=nil }

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
    sourceProfile,e:=privateC1SourceProfileMode()
    if e!=nil{return nil,e}
    return newC1SQLWithOpener(ctx,dsn,pgdata,sourceID,max,sourceProfile,
        privateC1CloneConnection,true)
}

// C1's native five-SQL engine runs in fi-sor. The connection opener is
// pinned at process construction; the original benchmark still refuses
// all non-clone addresses. No second relational ingestion algorithm exists.
func newC1SQLWithOpener(ctx context.Context,dsn,pgdata,sourceID string,
    max int,sourceProfile bool,
    open func(context.Context,string,string)(*pgx.Conn,int64,error),
    cloneOnly bool, targetSchema ...string,
)(*privateC1FiveSQL,error){
    if ctx==nil||sourceID==""||open==nil||max<1||max>privateC1HardSQLWorkersMax{
        return nil,errors.New("FI C1: incomplete or unbounded fi-sor SQL pool parameters")
    }
    schema:=privateProjectionSchema
    if len(targetSchema)>0 {
        if len(targetSchema)!=1||(targetSchema[0]!="fi_c1_pending"&&targetSchema[0]!="fi")||cloneOnly {
            return nil,errors.New("FI C1: private clone cannot redirect to governed pending or arbitrary schema")
        }
        schema=targetSchema[0]
    }
    owner,cancel:=context.WithCancel(ctx)
    w:=&privateC1FiveSQL{
        ctx:owner,cancel:cancel,sourceID:sourceID,dsn:dsn,pgdata:pgdata,
        openSQL:open,cloneOnly:cloneOnly,projectionSchema:schema,
        maxWorkers:max,sourceProfile:sourceProfile,sourceJobs:make(chan privateC1SourceJob,2),
        jobs:make(chan privateC1SQLJob,max*2),
        usnPending:make(chan privateC1SQLJob,privateC1MaxPendingUSNHandoffs),
        pids:make(map[int64]bool),
    }
    parent,pid,e:=w.openSQL(ctx,dsn,pgdata)
    if e!=nil{cancel();return nil,e}
    w.parent=parent
    w.parentBackendPID=pid
    if w.sourceProfile {
        // Label only the existing ordered writer. The 1-second read-only
        // PostgreSQL sampler uses this label to retrieve exact PID/waits.
        if _,e=parent.Exec(ctx,"SET application_name = 'fi-c1-sourceparent-8g'");e!=nil{
            cancel()
            _=parent.Close(context.Background())
            return nil,fmt.Errorf("FI C1: label ordered parent backend: %w",e)
        }
        fmt.Printf("FI C1 SOURCE PARENT BACKEND pid=%d application_name=fi-c1-sourceparent-8g single_connection=true clone_only=true\n",pid)
    }
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
    w.usnWG.Add(1)
    go w.runUSNDispatcher()
    fmt.Printf("FI C1 ASYNC USN DISPATCH START queue_max=%d ordered_SQL_commits=true file_dependencies=commit_fences shared_sql_workers=true extra_pg_connections=0\n",privateC1MaxPendingUSNHandoffs)
    fmt.Printf("FI C1 P6 NATIVE SQL BACKENDS parent=1 shared_workers_initial=1 workers_max=%d distinct_pids=2 fi_sor_sql_phase=true clone_only=%t\n",max,cloneOnly)
    return w,nil
}

// Called from the signed-reader goroutine to add ONE verified PostgreSQL
// session. Workers are never pinned to Security, File, Coverage, USN or Other.
func (w *privateC1FiveSQL) startWorker(ctx context.Context)error{
    if w.openSQL==nil{return errors.New("FI C1: unbound SQL connection opener")}
    conn,pid,err:=w.openSQL(ctx,w.dsn,w.pgdata)
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
            if job.family==privateP6USN&&err==nil{
                // Count SQL completion before publishing the consumer ACK,
                // so post-drain statistics cannot lag the last USN commit.
                w.usnCompleted++
            }
            w.mu.Unlock()
            if job.committed!=nil{
                job.committed.err=err
                close(job.committed.done)
            }
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

// runUSNDispatcher never touches the signed reader's outstanding slices.
// It submits exactly one USN job to the shared pool at a time. Each USN
// handoff carries broadcast commit fences for ALL earlier File handoffs,
// including those already running on different PostgreSQL connections.
// A SQL error fails this USN and every subsequently queued USN handoff;
// no incomplete generation can be published.
func (w *privateC1FiveSQL) runUSNDispatcher(){
    defer w.usnWG.Done()
    var failed error
    for job:=range w.usnPending{
        if failed==nil{
            waitStarted:=time.Now()
            for _,fileAck:=range job.filePrerequisites{
                if err:=privateC1AwaitSource(w.ctx,fileAck);err!=nil{
                    failed=fmt.Errorf("FI C1: USN File prerequisite SQL commit: %w",err)
                    break
                }
            }
            w.mu.Lock()
            w.usnFileWaitWall+=time.Since(waitStarted)
            w.mu.Unlock()
        }
        if failed==nil{
            select{
            case <-w.ctx.Done():
                failed=w.ctx.Err()
            case w.jobs<-job:
                // Shared SQL worker checks the exact source-parent ACK.
            }
            if failed==nil{
                waitStarted:=time.Now()
                failed=privateC1AwaitSource(w.ctx,job.committed)
                w.mu.Lock()
                w.usnSQLWaitWall+=time.Since(waitStarted)
                w.mu.Unlock()
                // The worker owns job.done; this branch MUST NOT consume
                // the result reserved for WaitFamily/the signed reader.
                continue
            }
        }
        // The job was never submitted to a SQL worker. Publish the
        // failure to BOTH independent ACK recipients without dropping it.
        job.committed.err=failed
        close(job.committed.done)
        job.done<-failed
        close(job.done)
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

// Merge already-captured COPY call distributions after each successful
// Security SQL module. This is constant-time per handoff and does not
// instrument COPY's hot row path, SQL, or transaction ordering.
func privateC1MergeCopyCallLatency(dst *copyCallLatency, src copyCallLatency){
    if dst==nil||src.Calls==0{return}
    if dst.Calls==0||src.Min<dst.Min{dst.Min=src.Min}
    if src.Max>dst.Max{dst.Max=src.Max}
    dst.Calls+=src.Calls
    dst.Total+=src.Total
    dst.AtLeastOneSecond+=src.AtLeastOneSecond
    dst.AtLeastFiveSeconds+=src.AtLeastFiveSeconds
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
    coordinator,err:=newPrivateP6SQLCoordinator(privateProjectionTx{Tx:tx,schema:w.projectionSchema,canonicalDirect:w.projectionSchema=="fi"},
        w.sourceID,profile)
    if err!=nil{return err}
    writeCtx,hashCopy,aceCopy,usnCopy:=privateC1BoundedProjectorContext(ctx)
    if lane.family==privateP6USN && !w.cloneOnly {
        // The C1 fi-sor worker reuses the original P6 USN projector, which
        // requires signed generation-scoped M6.1 capture state. The ordered
        // USN dispatcher persists each handoff independently; a fresh context
        // must restore earlier captures from the same Pending generation.
        writeCtx,err=c1SoRUSNCaptureContext(writeCtx,w.sourceID,w.usnGenerationID)
        if err!=nil{return err}
    }
    if !w.cloneOnly{
        // The constructor that sets cloneOnly=false is confined to the
        // authenticated local-socket fi-sor runtime. Retain the exact
        // frozen 65,536-row/16 MiB Security field COPY profile.
        writeCtx=context.WithValue(writeCtx,c1NativeFrozenSecurityContextKey{},true)
    }
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
        privateC1MergeCopyCallLatency(&s.SourceLatency,counters.SourceLatency)
        privateC1MergeCopyCallLatency(&s.EventLatency,counters.EventLatency)
        privateC1MergeCopyCallLatency(&s.ScopeLatency,counters.ScopeLatency)
        privateC1MergeCopyCallLatency(&s.FieldLatency,counters.FieldLatency)
        lane.mu.Unlock()
    }
    // The same privateProjectionTx rewrites all five family's COPY
    // targets into fi_recovery_projection. Drain *before* SQL COMMIT:
    // pending hashes/ACEs/USN changes and reasons are real FK children.
    projector:=privateProjectionTx{Tx:tx,schema:w.projectionSchema,canonicalDirect:w.projectionSchema=="fi"}
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
    // PostgreSQL COMMIT ACK is the only event that makes typed rows durable.
    // Do not count a queued or prepared SQL handoff as verified input.
    if w.commitReady!=nil{
        if err:=w.commitReady.CommitFamily(rows);err!=nil{
            return fmt.Errorf("FI C1: committed family readiness: %w",err)
        }
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
    beginWall:=time.Since(startedSource)
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    profile:=&ingestStageProfile{}
    var sourceCopyTiming privateC1SourceCopyTiming
    var sourceTx pgx.Tx=tx
    if w.sourceProfile {
        sourceTx=&privateC1TimedSourceTx{Tx:tx,timing:&sourceCopyTiming}
    }
    coordinator,err:=newPrivateP6SQLCoordinator(privateProjectionTx{Tx:sourceTx,schema:w.projectionSchema},
        w.sourceID,profile)
    sourceStarted:=time.Now()
    if err==nil{err=coordinator.Source(ctx,rows)}
    sourceWall:=time.Since(sourceStarted)
    if w.sourceProfile && err==nil {
        preCopy:=sourceWall-sourceCopyTiming.CopyWall
        if preCopy<0{preCopy=0}
        w.parentPreCopyWall+=preCopy
        w.parentCursorNextWall+=sourceCopyTiming.NextWall
        w.parentCursorValuesWall+=sourceCopyTiming.ValuesWall
        w.parentCOPYRemainderWall+=sourceCopyTiming.Remainder()
        w.parentProfiledCopyCalls+=sourceCopyTiming.Calls
        w.parentProfiledValues+=sourceCopyTiming.ValuesCalls
    }
    commitStarted:=time.Now()
    if err==nil{err=tx.Commit(ctx)}
    commitWall:=time.Since(commitStarted)
    if err!=nil{return fmt.Errorf("FI C1: ordered P6 source parent failed: %w",err)}
    readinessStarted:=time.Now()
    if w.commitReady!=nil{
        if err:=w.commitReady.CommitSource(rows);err!=nil{
            return fmt.Errorf("FI C1: committed source readiness: %w",err)
        }
    }
    readinessWall:=time.Since(readinessStarted)
    w.parentRows+=int64(len(rows))
    w.parentHandoffs++
    w.parentSQLWall+=time.Since(startedSource)
    w.parentBeginWall+=beginWall
    w.parentCopyWall+=profile.SourceSQL
    w.parentCommitWall+=commitWall
    w.parentReadinessWall+=readinessWall
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
        waited:=time.Since(started)
        w.sourceBackpressureWall+=waited
        if waited>=300*time.Millisecond{
            fmt.Printf("FI C1 STALL EVENT utc=%s stage=SQL_SOURCE_PARENT_BACKPRESSURE wait=%s outstanding=%d error=%t\n",
                time.Now().UTC().Format(time.RFC3339Nano),waited,len(w.sourceOutstanding),err!=nil)
        }
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
        waited:=time.Since(started)
        lane.backpressureWaitWall+=waited
        if waited>=300*time.Millisecond{
            fmt.Printf("FI C1 STALL EVENT utc=%s stage=SQL_FAMILY_ACK_BACKPRESSURE family=%s wait=%s outstanding=%d error=%t\n",
                time.Now().UTC().Format(time.RFC3339Nano),
                privateP6FamilyNames[f],waited,len(lane.outstanding),err!=nil)
        }
        if err!=nil{return err}
    }
    if w.sourceLast==nil{return errors.New("FI C1: family has no ordered source-parent fence")}
    job:=privateC1SQLJob{family:f,rows:rows,source:w.sourceLast,
        done:make(chan error,1)}
    // Every family carries an independent COMMIT broadcast fence for the
    // fi-sor mTLS ACK writer. The original signed-reader FIFO still owns
    // job.done; no second goroutine may steal its ordered completion.
    job.committed=&privateC1SourceAck{done:make(chan struct{})}
    if f==privateP6USN{
        if w.usnPending==nil||w.lanes[privateP6File]==nil{
            return errors.New("FI C1: missing bounded asynchronous USN dispatcher or File prerequisites")
        }
        // Snapshot every earlier unresolved File SQL commit, not merely
        // the last File ACK: File handoffs themselves may run concurrently.
        job.filePrerequisites=append(job.filePrerequisites,
            w.lanes[privateP6File].fileReceipts...)
        select{
        case <-ctx.Done():return ctx.Err()
        case <-w.ctx.Done():return w.ctx.Err()
        case w.usnPending<-job:
        }
        lane.outstanding=append(lane.outstanding,job.done)
        lane.latestCommitted=job.committed
        if len(lane.outstanding)>w.usnPeakOutstanding{
            w.usnPeakOutstanding=len(lane.outstanding)
        }
        return nil
    }
    select{
    case <-ctx.Done():return ctx.Err()
    case <-w.ctx.Done():return w.ctx.Err()
    case w.jobs<-job:
    }
    lane.outstanding=append(lane.outstanding,job.done)
    lane.latestCommitted=job.committed
    if f==privateP6File{
        lane.fileReceipts=append(lane.fileReceipts,job.committed)
    }
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
        if f==privateP6File{
            if len(lane.fileReceipts)==0{
                return errors.New("FI C1: missing File commit broadcast fence")
            }
            lane.fileReceipts[0]=nil
            lane.fileReceipts=lane.fileReceipts[1:]
        }
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
    parentOther:=w.parentSQLWall-w.parentBeginWall-w.parentCopyWall-
        w.parentCommitWall-w.parentReadinessWall
    if parentOther<0{parentOther=0}
    fmt.Printf("FI C1 SOURCE PARENT STAGES rows=%d handoffs=%d total=%s begin=%s copy=%s commit=%s commit_readiness=%s other=%s single_connection=true no_schema_change=true\n",
        w.parentRows,w.parentHandoffs,w.parentSQLWall,w.parentBeginWall,
        w.parentCopyWall,w.parentCommitWall,w.parentReadinessWall,parentOther)

    if w.sourceProfile {
        fmt.Printf("FI C1 SOURCE PARENT COPY DETAIL backend_pid=%d rows=%d handoffs=%d copy_calls=%d values_calls=%d pre_copy=%s cursor_next=%s cursor_values=%s copy_remainder=%s copy_total=%s commit=%s commit_readiness=%s phase_remainder_includes_pgx_encode_io_server=true one_parent_connection=true clone_only=true\n",
            w.parentBackendPID,w.parentRows,w.parentHandoffs,
            w.parentProfiledCopyCalls,w.parentProfiledValues,
            w.parentPreCopyWall,w.parentCursorNextWall,w.parentCursorValuesWall,
            w.parentCOPYRemainderWall,w.parentCopyWall,w.parentCommitWall,w.parentReadinessWall)
    }
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
            privateP6FamilyNames[lane.family],w.familyHandoffLimit(lane.family),
            lane.backpressureWaits,lane.backpressureWaitWall,len(lane.outstanding))
    }
    w.mu.Lock()
    fmt.Printf("FI C1 ASYNC USN DISPATCH COMPLETE queue_max=%d peak_outstanding=%d committed_handoffs=%d file_dependency_wait=%s ordered_sql_wait=%s reader_backpressure_waits=%d reader_backpressure_wall=%s ordered_commit=true shared_sql=true\n",
        privateC1MaxPendingUSNHandoffs,w.usnPeakOutstanding,
        w.usnCompleted,w.usnFileWaitWall,w.usnSQLWaitWall,
        w.lanes[privateP6USN].backpressureWaits,
        w.lanes[privateP6USN].backpressureWaitWall)
    w.mu.Unlock()
    s:=w.lanes[privateP6Security].securityCopies
    fmt.Printf("FI C1 SECURITY COPY PROFILE batches=%d events=%d scopes=%d fields=%d source_bytes=%d source_copy=%s event_copy=%s scope_copy=%s field_copy=%s child_prepare=%s bulk_id_lookup=%s bulk_prepare=%s\n",
        s.Batches,s.Events,s.Scopes,s.Fields,s.SourceBytes,
        s.SourceCopy,s.EventCopy,s.ScopeCopy,s.FieldCopy,
        s.ChildPrepare,s.IDLookup,s.Prepare)
    // Call totals are the SUM over concurrent SQL workers, not elapsed
    // ingestion wall time. A long call includes client encode and PG waits.
    var avgFieldRows float64
    if s.FieldLatency.Calls>0{
        avgFieldRows=float64(s.Fields)/float64(s.FieldLatency.Calls)
    }
    fieldMaxRows,fieldMaxBytes:=32768,8<<20
    if os.Getenv("FI_C1_SECURITY_8G_EXPERIMENT")=="1" {
        fieldMaxRows,fieldMaxBytes=65536,16<<20
    }
    fmt.Printf("FI C1 SECURITY COPY CALL PROFILE event_calls=%d event_max=%s event_ge_1s=%d scope_calls=%d scope_max=%s scope_ge_1s=%d field_calls=%d field_rows=%d field_rows_per_call=%.2f field_max_rows=%d field_max_bytes=%d field_call_min=%s field_call_max=%s field_ge_1s=%d field_ge_5s=%d field_total=%s concurrent_time_sum=true\n",
        s.EventLatency.Calls,s.EventLatency.Max,s.EventLatency.AtLeastOneSecond,
        s.ScopeLatency.Calls,s.ScopeLatency.Max,s.ScopeLatency.AtLeastOneSecond,
        s.FieldLatency.Calls,s.Fields,avgFieldRows,fieldMaxRows,fieldMaxBytes,s.FieldLatency.Min,
        s.FieldLatency.Max,s.FieldLatency.AtLeastOneSecond,
        s.FieldLatency.AtLeastFiveSeconds,s.FieldLatency.Total)

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
    if w.usnPending!=nil{
        close(w.usnPending)
        w.usnWG.Wait() // all queued USN work finished before closing shared jobs
    }
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
