// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Development-only: independent family preparation lanes, selected solely
// by the pinned disposable W512 PostgreSQL clone overlay. SQL remains serial.
package recordingest

import (
    "bufio"
    "context"
    "errors"
    "fmt"
    "os"
    "strconv"
    "sync"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

const (
    privateFamilyP3Credits = 32
    privateFamilyP3Bytes int64 = 256 << 20
    privateFamilyP3SecurityWorkers = 2 // accepted P3 default, unchanged when sweep is unset
    privateFamilyP3GeneralWorkers = 4 // one each in the accepted P3 configuration
)

// The W512 sweep changes only clone-local worker topology via a strict
// environment gate. Unset means the original accepted Family P3 topology.
// 8 general workers are distributed File=2, Coverage=2, USN=2, Other=2.
// Security=8 or Security=16, 32 in-flight credits in both experiments.
type privateFamilyP3Topology struct {
    Security int
    General int
    Counts [spoolDispatchFamilyCount]int
    Sweep bool
}

func privateFamilyP3TopologyFromEnvironment()(privateFamilyP3Topology,error){
    config:=privateFamilyP3Topology{Security:privateFamilyP3SecurityWorkers,
        General:privateFamilyP3GeneralWorkers}
    for i:=range config.Counts {config.Counts[i]=1}
    config.Counts[spoolDispatchSecurity]=privateFamilyP3SecurityWorkers
    rawSecurity:=os.Getenv("FI_W512_P3_SECURITY_WORKERS")
    rawGeneral:=os.Getenv("FI_W512_P3_GENERAL_WORKERS")
    if rawSecurity=="" && rawGeneral=="" {return config,nil}
    sec,err:=strconv.Atoi(rawSecurity)
    if err!=nil || (sec!=8 && sec!=16) {
        return config,errors.New("FI W512 P3 sweep: Security workers must be exactly 8 or 16")
    }
    general,err:=strconv.Atoi(rawGeneral)
    if err!=nil || general!=8 {
        return config,errors.New("FI W512 P3 sweep: general workers must be exactly 8")
    }
    config.Security,config.General,config.Sweep=sec,general,true
    config.Counts[spoolDispatchSecurity]=sec
    for _,f:=range []spoolDispatchFamily{spoolDispatchFile,spoolDispatchCoverage,
        spoolDispatchUSN,spoolDispatchOther} {config.Counts[f]=2}
    return config,nil
}

type privateFamilyP3WorkerStat struct {
    Records uint64
    Bytes uint64
    Prepare time.Duration
    ReceiveWait time.Duration
    OutputWait time.Duration
}
type privateFamilyP3LaneStat struct {
    Workers int
    WorkersStats []privateFamilyP3WorkerStat
    DispatchCount uint64
    DispatchBytes uint64
    PeakDepth int
}
type privateFamilyP3Telemetry struct {
    Topology privateFamilyP3Topology
    Lanes [spoolDispatchFamilyCount]privateFamilyP3LaneStat
    InputRecords uint64
    InputBytes uint64
    mu sync.Mutex // reader-only peak queue accounting; workers use isolated per-worker slots
}
func (m *privateFamilyP3Telemetry) print(complete bool) {
    if m==nil{return}
    labels:=[spoolDispatchFamilyCount]string{"Security","File","Coverage","USNDependency","Other"}
    var total uint64
    for i:=range m.Lanes {
        lane:=&m.Lanes[i]
        var prepared,bytes uint64
        var active int
        var prepareNS,receiveNS,outputNS int64
        for wi,stat:=range lane.WorkersStats {
            if stat.Records!=0 {active++}
            prepared+=stat.Records
            bytes+=stat.Bytes
            prepareNS+=int64(stat.Prepare)
            receiveNS+=int64(stat.ReceiveWait)
            outputNS+=int64(stat.OutputWait)
            fmt.Printf("FI FAMILY P3 WORKER family=%s worker=%d records=%d bytes=%d prepare_ns=%d input_wait_ns=%d output_wait_ns=%d complete=%t\n",
                labels[i],wi,stat.Records,stat.Bytes,stat.Prepare.Nanoseconds(),
                stat.ReceiveWait.Nanoseconds(),stat.OutputWait.Nanoseconds(),complete)
        }
        total+=prepared
        fmt.Printf("FI FAMILY P3 LANE family=%s workers=%d active=%d dispatched=%d prepared=%d bytes=%d prepare_ns=%d input_wait_ns=%d output_wait_ns=%d max_queue_depth=%d complete=%t\n",
            labels[i],lane.Workers,active,lane.DispatchCount,prepared,bytes,
            prepareNS,receiveNS,outputNS,lane.PeakDepth,complete)
    }
    fmt.Printf("FI FAMILY P3 TOTAL input_records=%d input_bytes=%d prepared_records=%d complete=%t security_workers=%d general_workers=%d inflight=32 sql_writers=1\n",
        m.InputRecords,m.InputBytes,total,complete,m.Topology.Security,m.Topology.General)
}


// This admission controller bounds the *prepared-but-not-consumed* signed
// input bytes in addition to the global 32-record credit budget. It does not
// replace existing independently bounded SQL COPY buffers. A cancelled scan
// wakes all reservations, even if the writer has stopped after an error.
type privateFamilyP3Budget struct {
    mu sync.Mutex
    changed *sync.Cond
    used int64
    max int64
    peak int64
}

func newPrivateFamilyP3Budget(limit int64) *privateFamilyP3Budget {
    b := &privateFamilyP3Budget{max:limit}
    b.changed=sync.NewCond(&b.mu)
    return b
}

func (b *privateFamilyP3Budget) reserve(ctx context.Context, size int64) error {
    if b==nil || ctx==nil || size<=0 || size>b.max {
        return errors.New("FI family P3: signed record outside global budget")
    }
    b.mu.Lock()
    defer b.mu.Unlock()
    // Avoid registering a cancellation callback for the common case:
    // most W512 records fit without waiting for the global byte budget.
    if err:=ctx.Err();err!=nil{return err}
    if size<=b.max-b.used {
        b.used+=size
        if b.used>b.peak {b.peak=b.used}
        return nil
    }
    stop:=context.AfterFunc(ctx,func(){b.mu.Lock();b.changed.Broadcast();b.mu.Unlock()})
    defer stop()
    for size>b.max-b.used {
        if err:=ctx.Err();err!=nil {return err}
        b.changed.Wait()
    }
    if err:=ctx.Err();err!=nil{return err}
    b.used+=size
    if b.used>b.peak {b.peak=b.used}
    return nil
}

func (b *privateFamilyP3Budget) release(size int64) {
    if b==nil || size<=0{return}
    b.mu.Lock()
    b.used-=size
    if b.used<0 {panic("FI family P3: negative admitted bytes")}
    b.changed.Broadcast()
    b.mu.Unlock()
}

func (b *privateFamilyP3Budget) stats() (used,peak int64) {
    b.mu.Lock();defer b.mu.Unlock()
    return b.used,b.peak
}

// Each record family has an independent work queue, with the Security lane
// receiving 2 (control), 8, or 16 workers. Workers are pure: no PostgreSQL calls, transactions,
// writes, or source-order decisions. The ordered H16 writer still owns all
// SQL and the atomic W512 commit. The original signed bytes are copied once
// before the block reader reuses its storage.
func newPrivateFamilyP3PreparedStream(
    parent context.Context, reader *bufio.Reader, prepare privateHeaderPrepareFunc,
) (*privateParallelPreparedStream,error) {
    if parent==nil || reader==nil || prepare==nil {
        return nil,errors.New("FI family P3: reader, context and preparer required")
    }
    config,err:=privateFamilyP3TopologyFromEnvironment()
    if err!=nil{return nil,err}
    workerCount:=config.Security+config.General
    fmt.Printf("FI FAMILY P3 SCHEDULER lanes=5 workers=%d security_workers=%d general_workers=%d file_workers=%d coverage_workers=%d usn_workers=%d other_workers=%d credits=32 max_pending_bytes=%d sql_writers=1 atomic_window=true\n",
        workerCount,config.Security,config.General,config.Counts[spoolDispatchFile],
        config.Counts[spoolDispatchCoverage],config.Counts[spoolDispatchUSN],
        config.Counts[spoolDispatchOther],privateFamilyP3Bytes)
    ctx,cancel:=context.WithCancel(parent)
    var lanes [spoolDispatchFamilyCount]chan privateParallelLine
    for i:=range lanes {lanes[i]=make(chan privateParallelLine,privateFamilyP3Credits)}
    output:=make(chan privateParallelLine,privateFamilyP3Credits)
    budget:=newPrivateFamilyP3Budget(privateFamilyP3Bytes)
    telemetry:=&privateFamilyP3Telemetry{Topology:config}
    for i:=range telemetry.Lanes {
        telemetry.Lanes[i].Workers=config.Counts[i]
        telemetry.Lanes[i].WorkersStats=make([]privateFamilyP3WorkerStat,config.Counts[i])
    }
    s:=&privateParallelPreparedStream{
        cancel:cancel,done:make(chan struct{}),results:output,
        credits:make(chan struct{},privateFamilyP3Credits),
        nextOrdinal:1,reorder:make(map[int64]privateParallelLine),
        privateFamilyBudget:budget,privateFamilyP3Telemetry:telemetry,
    }
    for i:=0;i<privateFamilyP3Credits;i++ {s.credits<-struct{}{}}
    var workers sync.WaitGroup
    workers.Add(workerCount+1)

    go func(){
        defer workers.Done()
        defer func(){for i:=range lanes{close(lanes[i])}}()
        var ordinal int64
        metrics,err:=streamCanonicalSpoolBlocks(ctx,reader,
            privateHeaderFirstBlockBytes,privateHeaderFirstMaxRecordBytes,
            func(raw []byte,kind string,family spoolDispatchFamily)error{
                select{
                case <-ctx.Done():return ctx.Err()
                case <-s.credits:
                }
                // Reserve bytes AFTER obtaining a record credit, and BEFORE
                // allocating the owned line copy. If this fails, cancel and
                // stop the clone; no source record is silently discarded.
                if err:=budget.reserve(ctx,int64(len(raw)));err!=nil{return err}
                ordinal++
                row:=privateParallelLine{ordinal:ordinal,raw:append([]byte(nil),raw...),
                    headerKind:kind,headerFamily:family}
                // Only this reader changes per-lane dispatch counts/high-water.
                lane:=&telemetry.Lanes[family]
                lane.DispatchCount++
                lane.DispatchBytes+=uint64(len(raw))
                telemetry.InputRecords++
                telemetry.InputBytes+=uint64(len(raw))
                select {
                case <-ctx.Done():budget.release(int64(len(raw)));return ctx.Err()
                case lanes[family]<-row:
                    // len includes queued but not currently processing records.
                    depth:=len(lanes[family])
                    if depth>lane.PeakDepth {lane.PeakDepth=depth}
                    return nil
                }
            })
        // Next reads this only after worker completion/output channel close.
        s.readerTime=metrics.ReadTime
        fmt.Printf("FI FAMILY P3 BLOCK DISPATCH records=%d bytes=%d read_calls=%d security=%d file=%d coverage=%d usn=%d other=%d read=%s\n",
            metrics.Records,metrics.Bytes,metrics.ReadCalls,
            metrics.ByFamily[spoolDispatchSecurity],metrics.ByFamily[spoolDispatchFile],
            metrics.ByFamily[spoolDispatchCoverage],metrics.ByFamily[spoolDispatchUSN],
            metrics.ByFamily[spoolDispatchOther],metrics.ReadTime)
        if err!=nil && ctx.Err()==nil {
            // A scanner failure must reach the ordered writer as a hard error.
            // Reserve an ordinary credit for its next exact source ordinal.
            select{
            case <-ctx.Done():return
            case <-s.credits:
            }
            select{
            case <-ctx.Done():return
            case output<-privateParallelLine{ordinal:ordinal+1,
                readErr:fmt.Errorf("FI family P3 signed source: %w",err)}:
            }
        }
    }()

    for family:=range lanes {
        lane:=spoolDispatchFamily(family)
        copies:=config.Counts[family]
        for i:=0;i<copies;i++ {
            go func(f spoolDispatchFamily,workerIndex int){
                defer workers.Done()
                stat:=&telemetry.Lanes[f].WorkersStats[workerIndex]
                for {
                    var line privateParallelLine
                    var ok bool
                    waitStart:=time.Now()
                    select{
                    case <-ctx.Done():return
                    case line,ok=<-lanes[f]:
                    }
                    stat.ReceiveWait+=time.Since(waitStart)
                    if !ok{return}
                    started:=time.Now()
                    line.source,line.security,line.selected,line.prepareErr=
                        prepare(line.raw,line.headerKind,f)
                    line.prepareTime=time.Since(started)
                    stat.Prepare+=line.prepareTime
                    stat.Records++
                    stat.Bytes+=uint64(len(line.raw))
                    outputStart:=time.Now()
                    select{
                    case <-ctx.Done():return
                    case output<-line:
                        stat.OutputWait+=time.Since(outputStart)
                    }
                }
            }(lane,i)
        }
    }
    go func(){workers.Wait();close(output);close(s.done)}()
    return s,nil
}

type privateFamilyP3CoverageValue struct {
    value records.WindowsSecurityCoverageObservation
    observedAt time.Time
}

// This function is used only in the C220 clone. File and Coverage payload
// validation and decoding run on their independent lane workers rather than
// consuming the serial SQL writer. The existing SQL projection validates
// again where necessary and preserves all original relational semantics.
func privateFamilyP3Prepare(raw []byte,kind string,family spoolDispatchFamily)(
    SourceRecord,securityBulkRecord,bool,error,
){
    source,security,selected,err:=privateHeaderFirstPrepare(raw,kind,family)
    if err!=nil{return source,security,selected,err}
    switch kind {
    case "FileObservation":
        var value fileObservationPayload
        if err=decodeStrictPayload(source.Record.Payload,&value);err!=nil {
            return source,security,selected,projectionDecodeError(kind,err)
        }
        value.NTFS.ContentHashes=&value.ContentHashes
        if err=ntfs.ValidateObservation(value.NTFS);err!=nil {
            return source,security,selected,projectionValidationError(kind,err)
        }
        if value.NTFS.GovernedRoot.ScopeID!=source.Record.ScopeID {
            return source,security,selected,errors.New("FI family P3: File governed-root scope differs from signed source")
        }
        source.PrivateFamilyP3File=&value
    case "WindowsSecurityCoverage":
        var value records.WindowsSecurityCoverageObservation
        if err=decodeStrictPayload(source.Record.Payload,&value);err!=nil {
            return source,security,selected,projectionDecodeError(kind,err)
        }
        if err=records.ValidateWindowsSecurityCoverageObservation(value);err!=nil{
            return source,security,selected,projectionValidationError(kind,err)
        }
        observedAt,e:=parseRFC3339(value.ObservedAt,"windows_security_coverage.observed_at")
        if e!=nil{return source,security,selected,e}
        source.PrivateFamilyP3Coverage=&privateFamilyP3CoverageValue{value:value,observedAt:observedAt}
    }
    return source,security,selected,nil
}
