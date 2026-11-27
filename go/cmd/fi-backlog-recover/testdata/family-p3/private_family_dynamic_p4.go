// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Disposable W512 private clone ONLY. Work-conserving, independent family
// scheduling: 2 initial worker goroutines per family, up to 16 on demand.
// Workers 0..n-1 are preferred in order whenever available. No family
// or individual worker waits for a full batch before starting preparation.
// The existing ordered H16 SQL writer owns all writes and W512 atomic commits.
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

const (
    privateDynamicMinWorkers = 2
    privateDynamicMaxWorkers = 16
)

// Keep these strict environment inputs confined to the disposable test;
// ordinary FI and the frozen A8, B16, G4 benchmarks do not select them.
func privateDynamicP4Selected() bool {
    return os.Getenv("FI_W512_P3_DYNAMIC_MIN")!="" ||
        os.Getenv("FI_W512_P3_DYNAMIC_MAX")!=""
}

func privateDynamicP4Gate() error {
    if os.Getenv("FI_W512_P3_DYNAMIC_MIN")!="2" ||
        os.Getenv("FI_W512_P3_DYNAMIC_MAX")!="16" ||
        os.Getenv("FI_W512_P3_SECURITY_WORKERS")!="" ||
        os.Getenv("FI_W512_P3_GENERAL_WORKERS")!="" {
        return errors.New("FI private dynamic P4: require min=2 max=16 and no fixed-worker override")
    }
    return nil
}

type privateDynamicP4Lane struct {
    family spoolDispatchFamily
    input <-chan privateParallelLine
    output chan<- privateParallelLine
    telemetry *privateFamilyP3Telemetry
    preparer privateHeaderPrepareFunc
    ctx context.Context
    wg *sync.WaitGroup

    ready chan int
    jobs [privateDynamicMaxWorkers]chan privateParallelLine
    live int // spawned worker count (monotonic until signed-batch finish)
    busy [privateDynamicMaxWorkers]bool
    pending []privateParallelLine
    peakBusy int
    scaleUps int
    dispatched int64
    peakPending int
}

// At every moment the first available worker in ascending index order
// receives the next record. All floor workers start immediately; overflow
// workers are created ONLY when all currently spawned workers are busy and
// there is work pending. Unlike buffered per-worker queues, this algorithm
// never puts a second item on one busy worker while another worker is free.
func (l *privateDynamicP4Lane) spawn() {
    id:=l.live
    l.jobs[id]=make(chan privateParallelLine)
    l.live++
    if l.live>privateDynamicMinWorkers {l.scaleUps++}
    l.wg.Add(1)
    go func(workerID int, ch <-chan privateParallelLine) {
        defer l.wg.Done()
        stat:=&l.telemetry.Lanes[l.family].WorkersStats[workerID]
        for {
            var line privateParallelLine
            var ok bool
            wait:=time.Now()
            select {
            case <-l.ctx.Done():return
            case line,ok=<-ch:
            }
            stat.ReceiveWait+=time.Since(wait)
            if !ok{return}
            started:=time.Now()
            line.source,line.security,line.selected,line.prepareErr=
                l.preparer(line.raw,line.headerKind,l.family)
            line.prepareTime=time.Since(started)
            stat.Prepare+=line.prepareTime
            stat.Records++
            stat.Bytes+=uint64(len(line.raw))
            outputStart:=time.Now()
            select {
            case <-l.ctx.Done():return
            case l.output<-line:
                stat.OutputWait+=time.Since(outputStart)
            }
            // Completion is reported to exactly this family dispatcher.
            // Do not mark the worker idle until output was delivered.
            select {
            case <-l.ctx.Done():return
            case l.ready<-workerID:
            }
        }
    }(id,l.jobs[id])
}

func (l *privateDynamicP4Lane) available() int {
    for i:=0;i<l.live;i++ {
        if !l.busy[i] {return i}
    }
    return -1
}

func (l *privateDynamicP4Lane) sendPending() {
    for len(l.pending)>0 {
        id:=l.available()
        if id==-1 {
            if l.live==privateDynamicMaxWorkers{return}
            l.spawn()
            id=l.live-1
        }
        l.busy[id]=true
        nbusy:=0
        for i:=0;i<l.live;i++ {if l.busy[i]{nbusy++}}
        if nbusy>l.peakBusy {l.peakBusy=nbusy}
        line:=l.pending[0]
        l.pending[0]=privateParallelLine{}
        l.pending=l.pending[1:]
        // Unbuffered job channels ensure the assigned worker really takes
        // this record before the dispatcher hands it the next item.
        select {
        case <-l.ctx.Done():return
        case l.jobs[id]<-line:l.dispatched++
        }
    }
}

func (l *privateDynamicP4Lane) run() {
    defer l.wg.Done()
    for i:=0;i<privateDynamicMinWorkers;i++ {l.spawn()}
    open:=true
    busyCount:=0
    for {
        if l.ctx.Err()!=nil {break}
        l.sendPending()
        busyCount=0
        for i:=0;i<l.live;i++ {if l.busy[i]{busyCount++}}
        if !open && len(l.pending)==0 && busyCount==0 {break}
        // When the queue is empty we can accept new work immediately.
        // A full lane never holds up another lane's dispatcher.
        select {
        case <-l.ctx.Done():
            open=false
            l.pending=nil
            goto stop
        case id:=<-l.ready:
            if id<0 || id>=l.live || !l.busy[id] {
                panic("FI dynamic P4: duplicate or invalid worker completion")
            }
            l.busy[id]=false
        case line,ok:=<-l.input:
            if !ok {
                open=false
                l.input=nil
                continue
            }
            l.pending=append(l.pending,line)
            if len(l.pending)>l.peakPending {l.peakPending=len(l.pending)}
        }
    }
stop:
    for i:=0;i<l.live;i++ {close(l.jobs[i])}
    stats:=&l.telemetry.Lanes[l.family]
    stats.DynamicSpawned=l.live
    stats.DynamicScaleUps=l.scaleUps
    stats.DynamicPeakBusy=l.peakBusy
    stats.DynamicPeakPending=l.peakPending
    stats.DynamicAssigned=l.dispatched
}

func newPrivateDynamicP4PreparedStream(
    parent context.Context, reader *bufio.Reader, prepare privateHeaderPrepareFunc,
) (*privateParallelPreparedStream,error) {
    if parent==nil || reader==nil || prepare==nil {
        return nil,errors.New("FI dynamic P4: context, reader and preparer required")
    }
    if err:=privateDynamicP4Gate();err!=nil{return nil,err}
    ctx,cancel:=context.WithCancel(parent)
    var familyInputs [spoolDispatchFamilyCount]chan privateParallelLine
    for f:=range familyInputs {
        familyInputs[f]=make(chan privateParallelLine,privateFamilyP3Credits)
    }
    output:=make(chan privateParallelLine,privateFamilyP3Credits)
    budget:=newPrivateFamilyP3Budget(privateFamilyP3Bytes)
    cfg:=privateFamilyP3Topology{Security:privateDynamicMaxWorkers,
        General:privateDynamicMaxWorkers*(int(spoolDispatchFamilyCount)-1),
        Dynamic:true,Min:privateDynamicMinWorkers,Max:privateDynamicMaxWorkers}
    telemetry:=&privateFamilyP3Telemetry{Topology:cfg}
    for f:=range telemetry.Lanes {
        cfg.Counts[f]=privateDynamicMaxWorkers
        telemetry.Lanes[f].Workers=privateDynamicMaxWorkers
        telemetry.Lanes[f].WorkersStats=make([]privateFamilyP3WorkerStat,privateDynamicMaxWorkers)
    }
    telemetry.Topology=cfg
    s:=&privateParallelPreparedStream{
        cancel:cancel,done:make(chan struct{}),results:output,
        credits:make(chan struct{},privateFamilyP3Credits),
        nextOrdinal:1,reorder:make(map[int64]privateParallelLine),
        privateFamilyBudget:budget,privateFamilyP3Telemetry:telemetry,
    }
    for i:=0;i<privateFamilyP3Credits;i++ {s.credits<-struct{}{}}
    fmt.Printf("FI FAMILY P3 SCHEDULER lanes=5 mode=dynamic priority_fill=true min_workers=2 max_workers=16 max_worker_slots=80 credits=32 max_pending_bytes=%d sql_writers=1 atomic_window=true\n",
        privateFamilyP3Bytes)
    // One reader, five independent dispatch coordinators and 2..16 actual
    // workers for each family. WaitGroup remains nonzero while dispatchers
    // spawn workers, ensuring Add is safe concurrently with Wait.
    var all sync.WaitGroup
    all.Add(1+int(spoolDispatchFamilyCount))
    for i:=range familyInputs {
        lane:=&privateDynamicP4Lane{
            family:spoolDispatchFamily(i),input:familyInputs[i],output:output,
            telemetry:telemetry,preparer:prepare,ctx:ctx,wg:&all,
            ready:make(chan int,privateDynamicMaxWorkers),
        }
        go lane.run()
    }
    go func(){
        defer all.Done()
        defer func(){for i:=range familyInputs {close(familyInputs[i])}}()
        var ordinal int64
        metrics,err:=streamCanonicalSpoolBlocks(ctx,reader,
            privateHeaderFirstBlockBytes,privateHeaderFirstMaxRecordBytes,
            func(raw []byte,kind string,family spoolDispatchFamily)error {
                select {
                case <-ctx.Done():return ctx.Err()
                case <-s.credits:
                }
                if err:=budget.reserve(ctx,int64(len(raw)));err!=nil {return err}
                ordinal++
                row:=privateParallelLine{ordinal:ordinal,raw:append([]byte(nil),raw...),
                    headerKind:kind,headerFamily:family}
                stat:=&telemetry.Lanes[family]
                stat.DispatchCount++
                stat.DispatchBytes+=uint64(len(raw))
                telemetry.InputRecords++
                telemetry.InputBytes+=uint64(len(raw))
                select {
                case <-ctx.Done():
                    budget.release(int64(len(raw)));return ctx.Err()
                case familyInputs[family]<-row:
                    if n:=len(familyInputs[family]);n>stat.PeakDepth {stat.PeakDepth=n}
                    return nil
                }
            })
        s.readerTime=metrics.ReadTime
        fmt.Printf("FI FAMILY P3 BLOCK DISPATCH records=%d bytes=%d read_calls=%d security=%d file=%d coverage=%d usn=%d other=%d read=%s\n",
            metrics.Records,metrics.Bytes,metrics.ReadCalls,
            metrics.ByFamily[spoolDispatchSecurity],metrics.ByFamily[spoolDispatchFile],
            metrics.ByFamily[spoolDispatchCoverage],metrics.ByFamily[spoolDispatchUSN],
            metrics.ByFamily[spoolDispatchOther],metrics.ReadTime)
        if err!=nil && ctx.Err()==nil {
            select {
            case <-ctx.Done():return
            case <-s.credits:
            }
            select {
            case <-ctx.Done():return
            case output<-privateParallelLine{ordinal:ordinal+1,
                readErr:fmt.Errorf("FI dynamic P4 signed source: %w",err)}:
            }
        }
    }()
    go func(){all.Wait();close(output);close(s.done)}()
    return s,nil
}
