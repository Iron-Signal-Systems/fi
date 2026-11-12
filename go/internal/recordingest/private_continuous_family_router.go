// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Development-only continuous source-first family router. This is the bounded
// routing core; it is not yet a PostgreSQL worker or accepted H16 profile.
// A durability-backed worker must implement the sink contract before enabling
// this router in signed recovery.
package recordingest

import (
    "context"
    "errors"
    "fmt"
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
    case "WindowsSecurityCoverage":
        return privateFamilyCoverage, nil
    case "USNReadBoundary", "USNObjectObservation":
        return privateFamilyUSN, nil
    case "CollectorIdentity", "DirectoryPrincipalSnapshot", "LocalPrincipalSnapshot",
        "NTFSCollectionError", "SMBShareSnapshot", "SupportingSourceCollectionError",
        "USNContinuityGap", "WindowsSecurityContinuityGap":
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
    finished bool
}

func newPrivateContinuousFamilyRouter(ctx context.Context, sink privateContinuousSink) (*privateContinuousFamilyRouter, error) {
    if ctx == nil || sink == nil {
        return nil, errors.New("FI continuous router: active context and durable sink required")
    }
    r := &privateContinuousFamilyRouter{
        sink: sink, sourceDurable: make(map[int]bool), outstanding: make(map[int]int64),
        confirmedThrough: -1,
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

func (r *privateContinuousFamilyRouter) Add(ctx context.Context, item privateContinuousRecord) error {
    if r == nil || r.sink == nil || r.finished || ctx == nil {
        return errors.New("FI continuous router: cannot add to inactive or finished stream")
    }
    if item.WindowIndex < 0 || item.SignedBatchIndex < 0 ||
        item.Ordinal <= 0 || item.SourceBatchID <= 0 ||
        item.Prepared.RecordBytes <= 0 {
        return errors.New("FI continuous router: invalid original signed identity or byte length")
    }
    if r.started &&
        (item.WindowIndex < r.lastWindow ||
            (item.WindowIndex == r.lastWindow &&
                (item.SignedBatchIndex < r.lastBatch ||
                    (item.SignedBatchIndex == r.lastBatch && item.Ordinal <= r.lastOrdinal)))) {
        return errors.New("FI continuous router: signed source stream out of order")
    }
    if r.sourceDurable[item.WindowIndex] {
        return errors.New("FI continuous router: source record arrived after its durable window close")
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
    if len(lane.pending) >= limit.Records ||
        (len(lane.pending) > 0 && incoming > limit.Bytes-lane.bytes) {
        if err := r.flush(ctx, family); err != nil {
            return err
        }
    }
    // A single oversized record cannot remain resident indefinitely.
    // A real SQL sink must own its projection atomically and the router
    // must keep a reference only as long as that bounded operation runs.
    if incoming > limit.Bytes {
        return fmt.Errorf("FI continuous router: record exceeds %s byte ceiling", family)
    }
    lane.pending = append(lane.pending, item)
    lane.bytes += incoming
    r.outstanding[item.WindowIndex]++
    r.lastWindow, r.lastBatch, r.lastOrdinal = item.WindowIndex, item.SignedBatchIndex, item.Ordinal
    r.started = true
    return nil
}

// SourceWindowClosed DOES NOT flush any type buffer. It verifies a durable
// source marker and leaves incomplete typed windows open; family buffers may
// cross any number of W128 or K32 boundaries.
func (r *privateContinuousFamilyRouter) SourceWindowClosed(ctx context.Context, windowIndex int) error {
    if r == nil || ctx == nil || !r.started || r.finished ||
        windowIndex != r.lastWindow || r.sourceDurable[windowIndex] {
        return errors.New("FI continuous router: invalid or duplicate source checkpoint")
    }
    if err := r.sink.SourceWindowDurable(ctx, windowIndex); err != nil {
        return fmt.Errorf("FI continuous router: durable source-window proof: %w", err)
    }
    r.sourceDurable[windowIndex] = true
    return r.markCompleted(ctx)
}

func (r *privateContinuousFamilyRouter) flush(ctx context.Context, family privateContinuousFamily) error {
    lane := &r.lanes[family]
    if len(lane.pending) == 0 {
        return nil
    }
    if err := r.sink.FlushFamily(ctx, family, lane.pending); err != nil {
        return fmt.Errorf("FI continuous router: %s SQL flush: %w", family, err)
    }
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
    for next := r.confirmedThrough+1; r.sourceDurable[next] && r.outstanding[next] == 0; next++ {
        if err := r.sink.MarkProjected(ctx, next); err != nil {
            return fmt.Errorf("FI continuous router: projected checkpoint %d: %w", next, err)
        }
        r.confirmedThrough = next
        delete(r.outstanding, next)
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
    if !r.started || !r.sourceDurable[r.lastWindow] {
        return errors.New("FI continuous router: final signed window not durably staged")
    }
    for family := privateFamilySecurity; family <= privateFamilyOrderedOther; family++ {
        if err := r.flush(ctx, family); err != nil {
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
