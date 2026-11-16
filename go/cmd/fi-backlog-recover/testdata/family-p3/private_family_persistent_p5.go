// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// P5 C220 private SQL-clone only. A P4-like dynamic priority-fill scheduler
// persists across all signed batches in one W512 typed transaction. A signed
// batch still owns its own strict ordinal stream, 32 credits, byte budget,
// source-hash/readback gates and ordered H16 SQL writer. No worker writes SQL.
package recordingest

import (
    "bufio"
    "context"
    "errors"
    "fmt"
    "os"
    "sync"
    "time"
)

type privateP5PoolContextKey struct{}

func privateP5Enabled() bool {
    return os.Getenv("FI_W512_P5_PERSISTENT")=="1"
}

type privateP5Task struct {
    line privateParallelLine
    stream *privateP5Session
}

type privateP5Session struct {
    ctx context.Context
    cancel context.CancelFunc
    pool *privateP5Pool
    output chan privateParallelLine
    wg sync.WaitGroup
    telemetry *privateFamilyP3Telemetry
    preparer privateHeaderPrepareFunc
    stateMu sync.Mutex
    active [spoolDispatchFamilyCount]int
    peakBusy [spoolDispatchFamilyCount]int
    peakPending [spoolDispatchFamilyCount]int
    scaleUps [spoolDispatchFamilyCount]int
}

func (s *privateP5Session) onAssign(f spoolDispatchFamily, scale bool, pending int) {
    s.stateMu.Lock()
    s.active[f]++
    if s.active[f]>s.peakBusy[f] {s.peakBusy[f]=s.active[f]}
    if pending>s.peakPending[f] {s.peakPending[f]=pending}
    if scale {s.scaleUps[f]++}
    s.stateMu.Unlock()
}
func (s *privateP5Session) onFinished(f spoolDispatchFamily) {
    s.stateMu.Lock()
    s.active[f]--
    if s.active[f]<0 {panic("FI P5: negative family task count")}
    s.stateMu.Unlock()
}
func (s *privateP5Session) afterClose() {
    s.stateMu.Lock()
    defer s.stateMu.Unlock()
    for i:=range s.telemetry.Lanes {
        lane:=&s.telemetry.Lanes[i]
        lane.DynamicSpawned=s.pool.lanes[i].spawned()
        lane.DynamicScaleUps=s.scaleUps[i]
        lane.DynamicPeakBusy=s.peakBusy[i]
        lane.DynamicPeakPending=s.peakPending[i]
        // Only successful job-channel sends are counted as assignments.
        lane.DynamicAssigned=int64(lane.DispatchCount)
    }
}

// Pool is never globally registered. It lives in an explicit context value,
// initialized and closed by the private typed-window caller. This makes
// cancellation, rollback and independent clone runs deterministic.
type privateP5Pool struct {
    ctx context.Context
    cancel context.CancelFunc
    windowIndex int
    wg sync.WaitGroup
    lanes [spoolDispatchFamilyCount]*privateP5Lane
    closeOnce sync.Once
}

type privateP5Lane struct {
    pool *privateP5Pool
    family spoolDispatchFamily
    input chan *privateP5Task
    started chan struct{}
    done chan int
    jobs [privateDynamicMaxWorkers]chan *privateP5Task
    busy [privateDynamicMaxWorkers]bool
    pending []*privateP5Task

    mu sync.Mutex
    live int
    peakBusy int
    maxQueued int
    scaleUps int
    processed uint64
    sessions uint64
}

func (l *privateP5Lane) spawned() int {
    l.mu.Lock()
    defer l.mu.Unlock()
    return l.live
}
func (l *privateP5Lane) spawn() {
    id:=l.live
    l.jobs[id]=make(chan *privateP5Task)
    l.mu.Lock()
    l.live++
    if id>=privateDynamicMinWorkers {l.scaleUps++}
    l.mu.Unlock()
    l.pool.wg.Add(1)
    go func(worker int, jobs <-chan *privateP5Task){
        defer l.pool.wg.Done()
        for {
            var task *privateP5Task
            select {
            case <-l.pool.ctx.Done():return
            case task=<-jobs:
            }
            if task==nil {return}
            s:=task.stream
            if s.ctx.Err()==nil {
                stat:=&s.telemetry.Lanes[l.family].WorkersStats[worker]
                started:=time.Now()
                task.line.source,task.line.security,task.line.selected,task.line.prepareErr=
                    s.preparer(task.line.raw,task.line.headerKind,l.family)
                task.line.prepareTime=time.Since(started)
                stat.Prepare+=task.line.prepareTime
                stat.Records++
                stat.Bytes+=uint64(len(task.line.raw))
                outputStarted:=time.Now()
                select {
                case <-s.ctx.Done():
                case <-l.pool.ctx.Done():
                case s.output<-task.line:
                    stat.OutputWait+=time.Since(outputStarted)
                }
            }
            s.onFinished(l.family)
            s.wg.Done()
            // Done is buffered, so a worker never waits for a reader or SQL
            // writer before becoming available for another signed batch.
            select {
            case <-l.pool.ctx.Done():return
            case l.done<-worker:
            }
        }
    }(id,l.jobs[id])
}

func (l *privateP5Lane) idleWorker() int {
    for i:=0;i<l.live;i++ {if !l.busy[i]{return i}}
    return -1
}

// Process completed tasks BEFORE deciding to scale up. Otherwise a
// buffered worker-completion notification can cause needless goroutine
// creation while an existing worker is actually idle.
func (l *privateP5Lane) drainCompletions(){
    for {
        select {
        case id:=<-l.done:
            if id<0 || id>=l.live || !l.busy[id] {
                panic("FI P5: invalid/duplicate worker completion")
            }
            l.busy[id]=false
        default:return
        }
    }
}

func (l *privateP5Lane) flushPending() {
    for len(l.pending)>0 {
        l.drainCompletions()
        task:=l.pending[0]
        if task.stream.ctx.Err()!=nil {
            l.pending[0]=nil
            l.pending=l.pending[1:]
            task.stream.wg.Done()
            continue
        }
        id:=l.idleWorker()
        scaled:=false
        if id<0 {
            if l.live==privateDynamicMaxWorkers{return}
            l.spawn()
            id=l.live-1
            scaled=true
        }
        l.busy[id]=true
        busy:=0
        for i:=0;i<l.live;i++ {if l.busy[i]{busy++}}
        if busy>l.peakBusy {l.peakBusy=busy}
        task.stream.onAssign(l.family,scaled,len(l.pending))
        l.pending[0]=nil
        l.pending=l.pending[1:]
        select {
        case <-l.pool.ctx.Done():
            task.stream.wg.Done()
            return
        case l.jobs[id]<-task:
            l.processed++
        }
    }
}

func (l *privateP5Lane) run() {
    defer l.pool.wg.Done()
    for i:=0;i<privateDynamicMinWorkers;i++ {l.spawn()}
    close(l.started)
    for {
        l.flushPending()
        select {
        case <-l.pool.ctx.Done():
            // Caller joins each batch session before pool cancellation.
            // Drain any canceled tasks defensively.
            for _,task:=range l.pending {task.stream.wg.Done()}
            l.pending=nil
            for i:=0;i<l.live;i++ {close(l.jobs[i])}
            return
        case id:=<-l.done:
            if id<0 || id>=l.live || !l.busy[id] {
                panic("FI P5: invalid/duplicate family worker completion")
            }
            l.busy[id]=false
        case task:=<-l.input:
            if task==nil {panic("FI P5: unexpected closed family input")}
            l.pending=append(l.pending,task)
            if len(l.pending)>l.maxQueued {l.maxQueued=len(l.pending)}
        }
    }
}

// Begin a window after its SQL transaction is established. All new batches
// share five independently bounded lanes and worker goroutines until Close.
// A fresh window always gets a fresh pool so no prep task can cross a
// failed atomic W512 transaction boundary.
func newPrivateP5Pool(ctx context.Context,windowIndex int)(*privateP5Pool,error){
    if ctx==nil || !privateP5Enabled() ||
        os.Getenv("FI_W512_P3_DYNAMIC_MIN")!="2" ||
        os.Getenv("FI_W512_P3_DYNAMIC_MAX")!="16" ||
        os.Getenv("FI_W512_P3_SECURITY_WORKERS")!="" ||
        os.Getenv("FI_W512_P3_GENERAL_WORKERS")!="" {
        return nil,errors.New("FI P5 private window: invalid explicit 2..16 scaling gate")
    }
    // Keep the pool alive long enough to DRAIN canceled batch tasks before
    // the typed-window's deferred Close. If we inherited ctx cancellation,
    // a lane could exit with queued session tasks and strand session.Close().
    poolCtx,cancel:=context.WithCancel(context.Background())
    p:=&privateP5Pool{ctx:poolCtx,cancel:cancel,windowIndex:windowIndex}
    p.wg.Add(int(spoolDispatchFamilyCount))
    for i:=range p.lanes{
        lane:=&privateP5Lane{pool:p,family:spoolDispatchFamily(i),
            input:make(chan *privateP5Task,privateFamilyP3Credits),
            started:make(chan struct{}),
            done:make(chan int,privateDynamicMaxWorkers)}
        p.lanes[i]=lane
        go lane.run()
    }
    // All five families have two real workers before the first batch.
    for _,lane:=range p.lanes {<-lane.started}
    fmt.Printf("FI P5 PERSISTENT WINDOW START window=%d families=5 worker_min=2 worker_max=16 credits=32 sql_writers=1\n",windowIndex)
    return p,nil
}
func (p *privateP5Pool) Close(){
    if p==nil{return}
    p.closeOnce.Do(func(){
        p.cancel()
        p.wg.Wait()
        for i:=range p.lanes{
            l:=p.lanes[i]
            fmt.Printf("FI P5 PERSISTENT WINDOW FAMILY window=%d family=%d spawned=%d scale_ups=%d peak_busy=%d max_queue=%d processed=%d complete=true\n",
                p.windowIndex,i,l.live,l.scaleUps,l.peakBusy,l.maxQueued,l.processed)
        }
        fmt.Printf("FI P5 PERSISTENT WINDOW STOP window=%d families=5 joined=true\n",p.windowIndex)
    })
}

func (p *privateP5Pool) newStream(
    parent context.Context,reader *bufio.Reader,prepare privateHeaderPrepareFunc,
)(*privateParallelPreparedStream,error){
    if p==nil||parent==nil||reader==nil||prepare==nil||p.ctx.Err()!=nil{
        return nil,errors.New("FI P5: missing persistent active pool, parent context, reader or preparer")
    }
    sessionCtx,sessionCancel:=context.WithCancel(parent)
    cfg:=privateFamilyP3Topology{Security:privateDynamicMaxWorkers,
        General:4*privateDynamicMaxWorkers,Dynamic:true,
        Min:privateDynamicMinWorkers,Max:privateDynamicMaxWorkers}
    metrics:=&privateFamilyP3Telemetry{Topology:cfg}
    for f:=range metrics.Lanes{
        cfg.Counts[f]=privateDynamicMaxWorkers
        metrics.Lanes[f].Workers=privateDynamicMaxWorkers
        metrics.Lanes[f].WorkersStats=make([]privateFamilyP3WorkerStat,privateDynamicMaxWorkers)
    }
    metrics.Topology=cfg
    sess:=&privateP5Session{ctx:sessionCtx,cancel:sessionCancel,
        pool:p,output:make(chan privateParallelLine,privateFamilyP3Credits),
        telemetry:metrics,preparer:prepare}
    s:=&privateParallelPreparedStream{
        cancel:sessionCancel,done:make(chan struct{}),results:sess.output,
        credits:make(chan struct{},privateFamilyP3Credits),
        nextOrdinal:1,reorder:make(map[int64]privateParallelLine),
        privateFamilyBudget:newPrivateFamilyP3Budget(privateFamilyP3Bytes),
        privateFamilyP3Telemetry:metrics,privateP5Session:sess,
    }
    for i:=0;i<privateFamilyP3Credits;i++ {s.credits<-struct{}{}}
    fmt.Printf("FI FAMILY P3 SCHEDULER lanes=5 mode=persistent priority_fill=true min_workers=2 max_workers=16 max_worker_slots=80 credits=32 max_pending_bytes=%d sql_writers=1 atomic_window=true\n",
        privateFamilyP3Bytes)
    sess.wg.Add(1) // Reader exists before any worker task / waiter.
    go func(){
        defer sess.wg.Done()
        var ordinal int64
        metrics,err:=streamCanonicalSpoolBlocks(sessionCtx,reader,
            privateHeaderFirstBlockBytes,privateHeaderFirstMaxRecordBytes,
            func(raw []byte,kind string,family spoolDispatchFamily)error{
                select {
                case <-sessionCtx.Done():return sessionCtx.Err()
                case <-s.credits:
                }
                if err:=s.privateFamilyBudget.reserve(sessionCtx,int64(len(raw)));err!=nil{return err}
                ordinal++
                row:=privateParallelLine{ordinal:ordinal,
                    raw:append([]byte(nil),raw...),headerKind:kind,headerFamily:family}
                stat:=&sess.telemetry.Lanes[family]
                stat.DispatchCount++
                stat.DispatchBytes+=uint64(len(raw))
                sess.telemetry.InputRecords++
                sess.telemetry.InputBytes+=uint64(len(raw))
                task:=&privateP5Task{line:row,stream:sess}
                sess.wg.Add(1)
                select {
                case <-sessionCtx.Done():
                    sess.wg.Done()
                    s.privateFamilyBudget.release(int64(len(raw)))
                    return sessionCtx.Err()
                case p.lanes[family].input<-task:
                    if n:=len(p.lanes[family].input);n>stat.PeakDepth {stat.PeakDepth=n}
                    return nil
                }
            })
        s.readerTime=metrics.ReadTime
        fmt.Printf("FI FAMILY P3 BLOCK DISPATCH records=%d bytes=%d read_calls=%d security=%d file=%d coverage=%d usn=%d other=%d read=%s\n",
            metrics.Records,metrics.Bytes,metrics.ReadCalls,
            metrics.ByFamily[spoolDispatchSecurity],metrics.ByFamily[spoolDispatchFile],
            metrics.ByFamily[spoolDispatchCoverage],metrics.ByFamily[spoolDispatchUSN],
            metrics.ByFamily[spoolDispatchOther],metrics.ReadTime)
        if err!=nil && sessionCtx.Err()==nil {
            select {
            case <-sessionCtx.Done():return
            case <-s.credits:
            }
            sess.wg.Add(1)
            select {
            case <-sessionCtx.Done():
                sess.wg.Done()
            case sess.output<-privateParallelLine{ordinal:ordinal+1,
                readErr:fmt.Errorf("FI P5 signed reader: %w",err)}:
                sess.wg.Done()
            }
        }
    }()
    go func(){sess.wg.Wait();close(sess.output);close(s.done)}()
    return s,nil
}
