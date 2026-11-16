// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Private C220 P4 only: bounded priority-fill scheduling with two to sixteen
// ACTIVE preparation workers per family. The original H16, header-first,
// Security Sweep and fixed G4 benchmarks remain unchanged.
package recordingest

import (
    "bufio"
    "context"
    "errors"
    "fmt"
    "sync"
    "time"
)

const (
    privateAdaptiveP4MinWorkers = 2
    privateAdaptiveP4MaxWorkers = 16
    privateAdaptiveP4IdleRetire = 150 * time.Millisecond
    privateAdaptiveP4IdlePoll = 25 * time.Millisecond
)

type privateAdaptiveP4LaneCounters struct {
    Activations uint64
    Retirements uint64
    PeakActive int
    ActiveAtEnd int
}

type privateAdaptiveP4Telemetry struct {
    Lanes [spoolDispatchFamilyCount]privateAdaptiveP4LaneCounters
}

// Called ONLY after the reader, five dispatchers, and dynamically spawned
// workers have ALL joined. A zero-work family still appears with two active
// workers at the start, zero retirements, and zero prepared records.
func (m *privateAdaptiveP4Telemetry) print(complete bool) {
    if m==nil{return}
    labels:=[spoolDispatchFamilyCount]string{
        "Security","File","Coverage","USNDependency","Other",
    }
    for f:=range m.Lanes {
        x:=m.Lanes[f]
        fmt.Printf("FI ADAPTIVE P4 LANE family=%s min_workers=2 max_workers=16 peak_active=%d activations=%d retirements=%d active_at_end=%d complete=%t\n",
            labels[f],x.PeakActive,x.Activations,x.Retirements,x.ActiveAtEnd,complete)
    }
    fmt.Printf("FI ADAPTIVE P4 COMPLETE families=5 min_workers=2 max_workers=16 credits=32 sql_writers=1 complete=%t\n",complete)
}

// Priority-fill: the lowest-index IDLE worker is selected first; additional
// workers are activated only if every active worker is currently busy.
// There is no batch-full or time-based delay before dispatching a ready row.
func privateAdaptiveP4LowestIdle(idle []bool, active int) int {
    for i:=0;i<active;i++ {if idle[i]{return i}}
    return -1
}

// The one dispatcher per family owns worker activation and retirement.
// Each worker has a one-record mailbox, not a shared work channel whose
// receive fairness could select worker 16 while worker 1 is idle.
// Worker index remains stable for within-family accounting. Worker goroutines
// never write PostgreSQL and never decide source/USN ordering.
func privateAdaptiveP4RunLane(
    ctx context.Context, family spoolDispatchFamily,
    input <-chan privateParallelLine,
    output chan<- privateParallelLine,
    prepare privateHeaderPrepareFunc,
    wg *sync.WaitGroup,
    fixed *privateFamilyP3Telemetry,
    adaptive *privateAdaptiveP4Telemetry,
) {
    var jobs [privateAdaptiveP4MaxWorkers]chan privateParallelLine
    var idle [privateAdaptiveP4MaxWorkers]bool
    var idleSince [privateAdaptiveP4MaxWorkers]time.Time
    done := make(chan int,privateAdaptiveP4MaxWorkers)
    active := 0
    inFlight := 0
    inputClosed := false
    stats:=&adaptive.Lanes[family]
    ticker:=time.NewTicker(privateAdaptiveP4IdlePoll)
    defer ticker.Stop()
    defer func() {
        // The waiter owns this only AFTER all output results have been
        // delivered (or the context is cancelled). All workers exit on the
        // closed mailbox or cancellation, and the outer WaitGroup joins them.
        for i:=0;i<active;i++ {if jobs[i]!=nil {close(jobs[i])}}
        stats.ActiveAtEnd=active
    }()

    complete:=func(id int){
        if id<0 || id>=active || idle[id] {
            // An impossible duplicate readiness must not silently produce
            // reordered SQL work. The stream's receipt validation will fail.
            return
        }
        idle[id]=true
        idleSince[id]=time.Now()
        inFlight--
    }
    drainReady:=func(){
        for {
            select{
            case id:=<-done: complete(id)
            default: return
            }
        }
    }
    startWorker:=func(){
        id:=active
        inbox:=make(chan privateParallelLine,1)
        jobs[id]=inbox
        idle[id]=true
        idleSince[id]=time.Now()
        active++
        stats.Activations++
        if active>stats.PeakActive {stats.PeakActive=active}
        wg.Add(1) // This dispatcher is itself still counted in wg.
        go func(workerIndex int,ch <-chan privateParallelLine){
            defer wg.Done()
            st:=&fixed.Lanes[family].WorkersStats[workerIndex]
            for {
                startedWait:=time.Now()
                var row privateParallelLine
                var ok bool
                select{
                case <-ctx.Done():return
                case row,ok=<-ch:
                }
                st.ReceiveWait+=time.Since(startedWait)
                if !ok {return}
                prepareStarted:=time.Now()
                row.source,row.security,row.selected,row.prepareErr=
                    prepare(row.raw,row.headerKind,family)
                row.prepareTime=time.Since(prepareStarted)
                st.Prepare+=row.prepareTime
                st.Records++
                st.Bytes+=uint64(len(row.raw))
                sendStarted:=time.Now()
                select{
                case <-ctx.Done():return
                case output<-row:
                    st.OutputWait+=time.Since(sendStarted)
                }
                select{
                case <-ctx.Done():return
                case done<-workerIndex:
                }
            }
        }(id,inbox)
    }
    for i:=0;i<privateAdaptiveP4MinWorkers;i++{startWorker()}

    for {
        drainReady()
        if inputClosed && inFlight==0 {return}
        select{
        case <-ctx.Done():return
        case id:=<-done:
            complete(id)
        case <-ticker.C:
            // Only the highest idle slot can retire: lower IDs remain the
            // priority target. Never retire below the floor of two.
            now:=time.Now()
            for active>privateAdaptiveP4MinWorkers {
                last:=active-1
                if !idle[last] || now.Sub(idleSince[last])<privateAdaptiveP4IdleRetire {break}
                close(jobs[last])
                jobs[last]=nil
                idle[last]=false
                active--
                stats.Retirements++
            }
        case row,ok:=<-input:
            if !ok {
                input=nil
                inputClosed=true
                continue
            }
            // Already-completed worker events take precedence over scaling.
            drainReady()
            id:=privateAdaptiveP4LowestIdle(idle[:],active)
            if id<0 && active<privateAdaptiveP4MaxWorkers {
                startWorker()
                id=active-1
            }
            // At 16 busy workers, hold this one row and wait for the first
            // completion. The upstream 32-credit budget remains bounded.
            for id<0 {
                select{
                case <-ctx.Done():return
                case finished:=<-done:
                    complete(finished)
                    drainReady()
                    id=privateAdaptiveP4LowestIdle(idle[:],active)
                }
            }
            idle[id]=false
            inFlight++
            select{
            case <-ctx.Done():return
            case jobs[id]<-row:
            }
        }
    }
}

// This API is selected ONLY by the P4 exact-anchor disposable overlay.
// It reuses accepted header-first source scanning and canonical family
// classification, and uses the unchanged 32-ordinal ordered SQL writer.
func newPrivateAdaptiveP4PreparedStream(
    parent context.Context, reader *bufio.Reader,
    prepare privateHeaderPrepareFunc,
) (*privateParallelPreparedStream,error) {
    if parent==nil || reader==nil || prepare==nil {
        return nil,errors.New("FI adaptive P4: missing immutable reader/context/preparer")
    }
    fmt.Printf("FI ADAPTIVE P4 SCHEDULER lanes=5 min_workers=2 max_workers=16 workers_max=80 credits=32 raw_budget_bytes=%d sql_writers=1 atomic_window=true priority_fill=true\n",
        privateFamilyP3Bytes)
    ctx,cancel:=context.WithCancel(parent)
    var lanes [spoolDispatchFamilyCount]chan privateParallelLine
    for i:=range lanes {lanes[i]=make(chan privateParallelLine,privateFamilyP3Credits)}
    output:=make(chan privateParallelLine,privateFamilyP3Credits)
    budget:=newPrivateFamilyP3Budget(privateFamilyP3Bytes)
    config:=privateFamilyP3Topology{Security:privateAdaptiveP4MaxWorkers,
        General:privateAdaptiveP4MaxWorkers*4,Sweep:true}
    telemetry:=&privateFamilyP3Telemetry{Topology:config}
    adaptive:=&privateAdaptiveP4Telemetry{}
    for f:=range telemetry.Lanes {
        telemetry.Lanes[f].Workers=privateAdaptiveP4MaxWorkers
        telemetry.Lanes[f].WorkersStats=make([]privateFamilyP3WorkerStat,
            privateAdaptiveP4MaxWorkers)
    }
    s:=&privateParallelPreparedStream{
        cancel:cancel,done:make(chan struct{}),results:output,
        credits:make(chan struct{},privateFamilyP3Credits),
        nextOrdinal:1,reorder:make(map[int64]privateParallelLine),
        privateFamilyBudget:budget,privateFamilyP3Telemetry:telemetry,
        privateAdaptiveP4Telemetry:adaptive,
    }
    for i:=0;i<privateFamilyP3Credits;i++ {s.credits<-struct{}{}}
    var workers sync.WaitGroup
    workers.Add(1+int(spoolDispatchFamilyCount))

    for f:=range lanes{
        family:=spoolDispatchFamily(f)
        go func(){
            defer workers.Done()
            privateAdaptiveP4RunLane(ctx,family,lanes[family],output,prepare,
                &workers,telemetry,adaptive)
        }()
    }

    go func(){
        defer workers.Done()
        defer func(){for i:=range lanes {close(lanes[i])}}()
        var ordinal int64
        metrics,err:=streamCanonicalSpoolBlocks(ctx,reader,
            privateHeaderFirstBlockBytes,privateHeaderFirstMaxRecordBytes,
            func(raw []byte,kind string,family spoolDispatchFamily)error{
                select{
                case <-ctx.Done():return ctx.Err()
                case <-s.credits:
                }
                if err:=budget.reserve(ctx,int64(len(raw)));err!=nil{return err}
                ordinal++
                row:=privateParallelLine{ordinal:ordinal,
                    raw:append([]byte(nil),raw...),headerKind:kind,headerFamily:family}
                lane:=&telemetry.Lanes[family]
                lane.DispatchCount++
                lane.DispatchBytes+=uint64(len(raw))
                telemetry.InputRecords++
                telemetry.InputBytes+=uint64(len(raw))
                select{
                case <-ctx.Done():
                    budget.release(int64(len(raw)))
                    return ctx.Err()
                case lanes[family]<-row:
                    if depth:=len(lanes[family]);depth>lane.PeakDepth{
                        lane.PeakDepth=depth
                    }
                    return nil
                }
            })
        s.readerTime=metrics.ReadTime
        fmt.Printf("FI ADAPTIVE P4 BLOCK DISPATCH records=%d bytes=%d read_calls=%d security=%d file=%d coverage=%d usn=%d other=%d read=%s\n",
            metrics.Records,metrics.Bytes,metrics.ReadCalls,
            metrics.ByFamily[spoolDispatchSecurity],metrics.ByFamily[spoolDispatchFile],
            metrics.ByFamily[spoolDispatchCoverage],metrics.ByFamily[spoolDispatchUSN],
            metrics.ByFamily[spoolDispatchOther],metrics.ReadTime)
        if err!=nil && ctx.Err()==nil{
            select{
            case <-ctx.Done():return
            case <-s.credits:
            }
            select{
            case <-ctx.Done():return
            case output<-privateParallelLine{ordinal:ordinal+1,
                readErr:fmt.Errorf("FI adaptive P4 signed source: %w",err)}:
            }
        }
    }()
    go func(){workers.Wait();close(output);close(s.done)}()
    return s,nil
}
