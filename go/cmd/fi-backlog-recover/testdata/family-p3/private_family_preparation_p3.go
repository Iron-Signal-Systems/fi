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
    "sync"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

const (
    privateFamilyP3Credits = 32
    privateFamilyP3Bytes int64 = 256 << 20
    privateFamilyP3SecurityWorkers = 2
)

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
// using two workers. Workers are pure: no PostgreSQL calls, transactions,
// writes, or source-order decisions. The ordered H16 writer still owns all
// SQL and the atomic W512 commit. The original signed bytes are copied once
// before the block reader reuses its storage.
func newPrivateFamilyP3PreparedStream(
    parent context.Context, reader *bufio.Reader, prepare privateHeaderPrepareFunc,
) (*privateParallelPreparedStream,error) {
    if parent==nil || reader==nil || prepare==nil {
        return nil,errors.New("FI family P3: reader, context and preparer required")
    }
    ctx,cancel:=context.WithCancel(parent)
    var lanes [spoolDispatchFamilyCount]chan privateParallelLine
    for i:=range lanes {lanes[i]=make(chan privateParallelLine,privateFamilyP3Credits)}
    output:=make(chan privateParallelLine,privateFamilyP3Credits)
    budget:=newPrivateFamilyP3Budget(privateFamilyP3Bytes)
    s:=&privateParallelPreparedStream{
        cancel:cancel,done:make(chan struct{}),results:output,
        credits:make(chan struct{},privateFamilyP3Credits),
        nextOrdinal:1,reorder:make(map[int64]privateParallelLine),
        privateFamilyBudget:budget,
    }
    for i:=0;i<privateFamilyP3Credits;i++ {s.credits<-struct{}{}}
    var workers sync.WaitGroup
    count:=int(spoolDispatchFamilyCount)+privateFamilyP3SecurityWorkers-1
    workers.Add(count+1)

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
                select {
                case <-ctx.Done():budget.release(int64(len(raw)));return ctx.Err()
                case lanes[family]<-row:return nil
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
        copies:=1
        if lane==spoolDispatchSecurity {copies=privateFamilyP3SecurityWorkers}
        for i:=0;i<copies;i++ {
            go func(f spoolDispatchFamily){
                defer workers.Done()
                for {
                    var line privateParallelLine
                    var ok bool
                    select{
                    case <-ctx.Done():return
                    case line,ok=<-lanes[f]:
                    }
                    if !ok{return}
                    started:=time.Now()
                    line.source,line.security,line.selected,line.prepareErr=
                        prepare(line.raw,line.headerKind,f)
                    line.prepareTime=time.Since(started)
                    select{
                    case <-ctx.Done():return
                    case output<-line:
                    }
                }
            }(lane)
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
