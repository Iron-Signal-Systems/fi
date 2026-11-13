// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Development-only W128 -> K32 -> independent typed-buffer dispatcher.
// K32 bounds CPU/input work, NOT PostgreSQL transaction boundaries. The
// independent family queues outlive each K32 chunk and each W128 input window.
package recordingest

import (
    "context"
    "errors"
    "fmt"
)

const (
    // PrivateContinuousK32Records pins the W128 sub-chunk scheduler's input bound.
    // It is not a PostgreSQL flush or commit threshold.
    PrivateContinuousK32Records = 32768
    privateContinuousK32MaxRecords = PrivateContinuousK32Records
    privateContinuousK32MaxBytes int64 = 256 << 20
)

// privateContinuousK32Chunk owns at most one K32 of decoded signed records.
// It does not stage or publish any additional custody authority. The W128
// source checkpoint is ALREADY durable before the first record is accepted.
// SourceRecord payloads are kept only until dispatched to the persistent
// cross-window family lanes, and cannot be used to mark typed completion.
type privateContinuousK32Chunk struct {
    router *privateContinuousFamilyRouter
    window int
    pending []privateContinuousRecord
    bytes int64
    chunks int
    dispatched uint64
    dispatchedBytes uint64
}

func newPrivateContinuousK32Chunk(router *privateContinuousFamilyRouter, window int) (*privateContinuousK32Chunk, error) {
    if router == nil || window < 0 || !router.windowOpen || router.lastWindow != window {
        return nil, errors.New("FI K32: requires the matching open durable W128 source window")
    }
    return &privateContinuousK32Chunk{
        router: router, window: window,
        pending: make([]privateContinuousRecord, 0, privateContinuousK32MaxRecords),
    }, nil
}

func (c *privateContinuousK32Chunk) Add(ctx context.Context, record privateContinuousRecord) error {
    if c == nil || c.router == nil || ctx == nil || c.window != record.WindowIndex ||
        !c.router.windowOpen || c.router.lastWindow != c.window {
        return errors.New("FI K32: invalid signed record, window or processing state")
    }
    if err := ctx.Err(); err != nil { return err }
    size := int64(record.Prepared.RecordBytes)
    if size <= 0 || size > privateContinuousK32MaxBytes {
        return errors.New("FI K32: original signed record outside bounded processing bytes")
    }
    if len(c.pending) == privateContinuousK32MaxRecords ||
        (len(c.pending) > 0 && size > privateContinuousK32MaxBytes - c.bytes) {
        if err := c.dispatch(ctx, false); err != nil { return err }
    }
    c.pending = append(c.pending, record)
    c.bytes += size
    if len(c.pending) == privateContinuousK32MaxRecords ||
        c.bytes == privateContinuousK32MaxBytes {
        return c.dispatch(ctx, false)
    }
    return nil
}

// dispatch submits each K32 record in ORIGINAL signed sequence to its family
// lane. This method must NEVER call flush/end-of-input on the family router.
// Only the receiving lane's capacity may cause its independent SQL commit.
// On SQL error the entire invocation stops; restart reconstructs records from
// the receiver-authenticated cache and idempotent SQL completion receipts.
func (c *privateContinuousK32Chunk) dispatch(ctx context.Context, finalPartial bool) error {
    if c == nil || ctx == nil { return errors.New("FI K32: dispatcher/context missing") }
    if len(c.pending) == 0 { return nil }
    count, size := len(c.pending), c.bytes
    first := c.pending[0]
    last := c.pending[count-1]
    for _, row := range c.pending {
        if err := c.router.Add(ctx, row); err != nil {
            return fmt.Errorf("FI K32: W%d chunk=%d route failed: %w", c.window, c.chunks, err)
        }
    }
    c.dispatched += uint64(count)
    c.dispatchedBytes += uint64(size)
    fmt.Printf("FI PRIVATE CONTINUOUS K32 DISPATCH window=%d chunk=%d records=%d bytes=%d partial=%t first_batch=%d last_batch=%d family_boundary_flush=false\n",
        c.window, c.chunks, count, size, finalPartial,
        first.SignedBatchIndex, last.SignedBatchIndex)
    c.chunks++
    c.pending = c.pending[:0]
    c.bytes = 0
    return nil
}

// EndSourceWindow dispatches only a short final K32 work unit. It does NOT
// empty any Security, File, coverage or ordered USN queue. The router closes
// the source window separately, and its family lanes continue across W128.
func (c *privateContinuousK32Chunk) EndSourceWindow(ctx context.Context) error {
    if c == nil || c.router == nil || !c.router.windowOpen || c.router.lastWindow != c.window {
        return errors.New("FI K32: end called without matching open W128 source window")
    }
    return c.dispatch(ctx, true)
}
