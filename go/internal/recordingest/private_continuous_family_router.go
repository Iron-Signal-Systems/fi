// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Development-only continuous source-first family router. This is the bounded
// routing core, wired to the private SQL family sink only by the isolated
// -private-continuous-family experiment. It is not the accepted H16 profile.
// All real relational writes require the signed durable source-window gate.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "time"
)

type privateContinuousFamily uint8

const (
    privateFamilySecurity privateContinuousFamily = iota + 1
    privateFamilyFile
    privateFamilyCoverage
    privateFamilyUSN
    privateFamilyOrderedOther
)

func (f privateContinuousFamily) String() string {
    switch f {
    case privateFamilySecurity:
        return "Security"
    case privateFamilyFile:
        return "File"
    case privateFamilyCoverage:
        return "SecurityCoverage"
    case privateFamilyUSN:
        return "USNDependency"
    case privateFamilyOrderedOther:
        return "OrderedOther"
    default:
        return "Invalid"
    }
}

func privateFamilyForRecordKind(kind string) (privateContinuousFamily, error) {
    switch kind {
    case "WindowsSecurityEvent":
        return privateFamilySecurity, nil
    case "FileObservation":
        return privateFamilyFile, nil
    case "WindowsSecurityCoverage", "WindowsSecurityContinuityGap":
        return privateFamilyCoverage, nil
    // Preserve the original ordered USN stream, including continuity loss.
    // A gap must never be delayed behind unrelated Security/File commits.
    case "USNReadBoundary", "USNObjectObservation", "USNContinuityGap":
        return privateFamilyUSN, nil
    case "CollectorIdentity", "DirectoryPrincipalSnapshot", "LocalPrincipalSnapshot",
        "NTFSCollectionError", "SMBShareSnapshot", "SupportingSourceCollectionError":
        return privateFamilyOrderedOther, nil
    default:
        return 0, fmt.Errorf("FI continuous family: unrecognized record kind %q", kind)
    }
}

// Original custody identity, independent of PostgreSQL-generated IDs.
// Once SourceWindowDurable succeeds, these records can be reconstructed on
// restart from the signed cache + fi_recovery.pending_source_record.
type privateContinuousRecord struct {
    WindowIndex int
    SignedBatchIndex int
    Ordinal int64
    SourceBatchID int64
    Prepared SourceRecord
}

type privateFamilyLimits struct {
    Records int
    Bytes int64
}

type privateContinuousLane struct {
    limits privateFamilyLimits
    pending []privateContinuousRecord
    bytes int64
}

// This interface MUST be implemented by durable SQL commits, not a memory
// counter. FlushFamily commits source rows, every relational child, and a
// replay-identifiable receipt in one transaction. SourceWindowDurable must
// verify an already committed fi_recovery.source_window checkpoint BEFORE
// the router accepts that window as durable. MarkProjected may insert a
// typed_window marker only after checking full per-window relational coverage.
type privateContinuousSink interface {
    SourceWindowDurable(ctx context.Context, windowIndex int) error
    FlushFamily(ctx context.Context, family privateContinuousFamily,
        batch []privateContinuousRecord) error
    MarkProjected(ctx context.Context, windowIndex int) error
}

type privateContinuousFamilyRouter struct {
    sink privateContinuousSink
    lanes [privateFamilyOrderedOther+1]privateContinuousLane
    lastWindow int
    lastBatch int
    lastOrdinal int64
    started bool
    sourceDurable map[int]bool
    outstanding map[int]int64
    confirmedThrough int
    windowOpen bool
    sourceClosed map[int]bool
    finished bool
}

// completedPrefix is the already verified contiguous typed-window prefix.
// W3-W4 replay starts at 2; a fresh ingest starts at -1.
func newPrivateContinuousFamilyRouter(ctx context.Context, sink privateContinuousSink,
    completedPrefix int) (*privateContinuousFamilyRouter, error) {
    if ctx == nil || sink == nil || completedPrefix < -1 {
        return nil, errors.New("FI continuous router: context, durable sink and valid completed prefix required")
    }
    r := &privateContinuousFamilyRouter{
        sink: sink, sourceDurable: make(map[int]bool),
        sourceClosed: make(map[int]bool), outstanding: make(map[int]int64),
        confirmedThrough: completedPrefix, lastWindow: completedPrefix, lastBatch: -1,
    }
    r.lanes[privateFamilySecurity].limits = privateFamilyLimits{Records: 4096, Bytes: 16 << 20}
    r.lanes[privateFamilyFile].limits = privateFamilyLimits{Records: 8192, Bytes: 32 << 20}
    r.lanes[privateFamilyCoverage].limits = privateFamilyLimits{Records: 512, Bytes: 8 << 20}
    r.lanes[privateFamilyUSN].limits = privateFamilyLimits{Records: 512, Bytes: 8 << 20}
    // Non-family-dependent records still need bounded memory and original
    // source ordering among themselves, but not a Security/File flush.
    r.lanes[privateFamilyOrderedOther].limits = privateFamilyLimits{Records: 512, Bytes: 8 << 20}
    return r, nil
}

// BeginSourceWindow checks that the source window has ALREADY committed in the
// separate fi_recovery.source_window chain. SQL capacity flushes may now run
// safely during record routing: the full signed source remains durable even if
// the worker crashes before a typed marker is committed.
func (r *privateContinuousFamilyRouter) BeginSourceWindow(ctx context.Context, windowIndex int) error {
    if r == nil || ctx == nil || r.finished || r.windowOpen ||
        windowIndex != r.lastWindow+1 {
        return errors.New("FI continuous router: source windows must begin once and in order")
    }
    if err := r.sink.SourceWindowDurable(ctx, windowIndex); err != nil {
        return fmt.Errorf("FI continuous router: source window %d not durable: %w", windowIndex, err)
    }
    r.sourceDurable[windowIndex] = true
    r.lastWindow = windowIndex
    r.lastBatch = -1
    r.lastOrdinal = 0
    r.started = true
    r.windowOpen = true
    return nil
}

func (r *privateContinuousFamilyRouter) Add(ctx context.Context, item privateContinuousRecord) error {
    if r == nil || r.sink == nil || r.finished || ctx == nil ||
        !r.windowOpen || item.WindowIndex != r.lastWindow {
        return errors.New("FI continuous router: records require a prior durable source-window checkpoint")
    }
    if item.WindowIndex < 0 || item.SignedBatchIndex < 0 ||
        item.Ordinal <= 0 || item.SourceBatchID <= 0 ||
        item.Prepared.RecordBytes <= 0 {
        return errors.New("FI continuous router: invalid original signed identity or byte length")
    }
    if item.SignedBatchIndex < r.lastBatch ||
        (item.SignedBatchIndex == r.lastBatch && item.Ordinal <= r.lastOrdinal) {
        return errors.New("FI continuous router: signed batch/ordinal sequence reversed")
    }
    family, err := privateFamilyForRecordKind(item.Prepared.Record.RecordKind)
    if err != nil {
        return err
    }
    lane := &r.lanes[family]
    limit := lane.limits
    incoming := int64(item.Prepared.RecordBytes)
    if limit.Records <= 0 || limit.Bytes <= 0 {
        return errors.New("FI continuous router: missing bounded lane limits")
    }
    // Reject an oversized source record BEFORE draining an unrelated
    // pending batch. Its rejection must not cause avoidable SQL work.
    if incoming > limit.Bytes {
        return fmt.Errorf("FI continuous router: record exceeds %s byte ceiling", family)
    }
    if len(lane.pending) >= limit.Records ||
        (len(lane.pending) > 0 && incoming > limit.Bytes-lane.bytes) {
        if err := r.flush(ctx, family, "capacity"); err != nil {
            return err
        }
    }
    lane.pending = append(lane.pending, item)
    lane.bytes += incoming
    r.outstanding[item.WindowIndex]++
    r.lastBatch, r.lastOrdinal = item.SignedBatchIndex, item.Ordinal
    // A buffer is full as soon as this record fills its record or byte
    // ceiling. Do not wait for another source record to arrive: a signed
    // window can end on the exact limit, and capacity (not that later
    // window boundary) must be the recorded reason for SQL delivery.
    if len(lane.pending) == limit.Records || lane.bytes == limit.Bytes {
        return r.flush(ctx, family, "capacity")
    }
    return nil
}

// EndSourceWindow closes the INPUT range only. Neither K32 nor W128
// empties a partial family buffer, and a typed marker is not created while
// the source records of that window remain pending.
func (r *privateContinuousFamilyRouter) EndSourceWindow(ctx context.Context, windowIndex int) error {
    if r == nil || ctx == nil || r.finished || !r.windowOpen ||
        windowIndex != r.lastWindow || !r.sourceDurable[windowIndex] {
        return errors.New("FI continuous router: no such active durable source window")
    }
    r.windowOpen = false
    r.sourceClosed[windowIndex] = true
    return r.markCompleted(ctx)
}

func (r *privateContinuousFamilyRouter) flush(ctx context.Context, family privateContinuousFamily, reason string) error {
    lane := &r.lanes[family]
    if len(lane.pending) == 0 {
        return nil
    }
    if reason!="capacity" && reason!="end-of-input" {
        return errors.New("FI continuous router: invalid SQL flush trigger")
    }
    records:=len(lane.pending)
    bytes:=lane.bytes
    first:=lane.pending[0]
    last:=lane.pending[records-1]
    started:=time.Now()
    if err := r.sink.FlushFamily(ctx, family, lane.pending); err != nil {
        return fmt.Errorf("FI continuous router: %s SQL flush: %w", family, err)
    }
    // This proof line is emitted ONLY after PostgreSQL reports a committed
    // family transaction, not at the caller's W128 or K32 source boundary.
    fmt.Printf("FI PRIVATE CONTINUOUS FAMILY FLUSH family=%s trigger=%s records=%d bytes=%d first_window=%d last_window=%d first_batch=%d last_batch=%d elapsed=%s\n",
        family,reason,records,bytes,first.WindowIndex,last.WindowIndex,
        first.SignedBatchIndex,last.SignedBatchIndex,time.Since(started))
    // Release records ONLY after the sink reports its SQL transaction
    // committed. A failure keeps the original queue available for replay.
    for _, row := range lane.pending {
        r.outstanding[row.WindowIndex]--
        if r.outstanding[row.WindowIndex] < 0 {
            return errors.New("FI continuous router: negative pending source count")
        }
    }
    lane.pending = nil
    lane.bytes = 0
    return r.markCompleted(ctx)
}

func (r *privateContinuousFamilyRouter) markCompleted(ctx context.Context) error {
    // Typed-window markers remain contiguous. If one family still has a
    // partial buffer from W3, W3 stays pending even if W4 source is durable.
    for next := r.confirmedThrough+1; r.sourceClosed[next] &&
        r.sourceDurable[next] && r.outstanding[next] == 0; next++ {
        if err := r.sink.MarkProjected(ctx, next); err != nil {
            return fmt.Errorf("FI continuous router: projected checkpoint %d: %w", next, err)
        }
        r.confirmedThrough = next
        delete(r.outstanding, next)
        fmt.Printf("FI PRIVATE CONTINUOUS TYPED COMMIT window=%d outstanding=0\n",next)
    }
    return nil
}

// EndOfInput is the ONLY unconditional flush of partial buffers. Unlike
// K32/W128 source boundaries, it represents the user's actual processing
// stop and can close all outstanding fully sourced windows.
func (r *privateContinuousFamilyRouter) EndOfInput(ctx context.Context) error {
    if r == nil || ctx == nil || r.finished {
        return errors.New("FI continuous router: invalid end-of-input")
    }
    if !r.started || r.windowOpen || !r.sourceClosed[r.lastWindow] ||
        !r.sourceDurable[r.lastWindow] {
        return errors.New("FI continuous router: final signed source window has not closed")
    }
    for family := privateFamilySecurity; family <= privateFamilyOrderedOther; family++ {
        if err := r.flush(ctx, family, "end-of-input"); err != nil {
            return err
        }
    }
    if err := r.markCompleted(ctx); err != nil {
        return err
    }
    if r.confirmedThrough != r.lastWindow {
        return errors.New("FI continuous router: incomplete typed projection at end of source")
    }
    r.finished = true
    return nil
}
