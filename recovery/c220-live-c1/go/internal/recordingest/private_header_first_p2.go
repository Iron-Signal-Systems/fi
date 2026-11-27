//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Experimental W512 private clone only: header-first, block-read preparation.
// This source is not wired into the normal FI ingest implementation.
package recordingest

import (
    "bufio"
    "context"
    "errors"
    "fmt"
    "sync"
    "time"
)

// Keep Candidate A's two workers and four-record ordering budget fixed for the
// first identical-data A/B. These are NOT the independent typed SQL buffers.
const (
    privateHeaderFirstBlockBytes = 4 << 20
    privateHeaderFirstMaxRecordBytes = 64 << 20
)

type privateHeaderPrepareFunc func([]byte, string, spoolDispatchFamily) (SourceRecord, securityBulkRecord, bool, error)

// The dispatcher identifies kind BEFORE any payload decoding. Each family
// processor will eventually own its SQL-row transformation. For this first
// private A/B, use unchanged typed preparation and COPY semantics so only
// routing and the block reader differ from the accepted H16 P2 baseline.
func privateHeaderFirstPrepare(raw []byte, kind string, family spoolDispatchFamily) (SourceRecord, securityBulkRecord, bool, error) {
    var emptySource SourceRecord
    var emptySecurity securityBulkRecord
    if family == spoolDispatchSecurity && kind == "WindowsSecurityEvent" {
        source, security, selected, err := tryPrepareSinglePassSecurity(raw)
        if err != nil || selected {
            if err == nil && source.Record.RecordKind != kind {
                return emptySource, emptySecurity, false, errors.New("FI header-first Security kind changed after decode")
            }
            return source, security, selected, err
        }
    }
    source, err := prepareOwnedSourceRecord(raw)
    if err != nil { return emptySource, emptySecurity, false, err }
    if source.Record.RecordKind != kind {
        return emptySource, emptySecurity, false, errors.New("FI header-first kind changed after decode")
    }
    return source, emptySecurity, false, nil
}

// The original Candidate A writer still consumes this stream and owns all
// PostgreSQL writes/transaction boundaries. This constructor is selected
// ONLY by the isolated W512 candidate overlay.
func newPrivateHeaderFirstPreparedStream(
    parent context.Context, reader *bufio.Reader, prepare privateHeaderPrepareFunc,
) (*privateParallelPreparedStream, error) {
    if parent == nil || reader == nil || prepare == nil {
        return nil, errors.New("FI header-first P2: nil reader, context, or preparer")
    }
    ctx, cancel := context.WithCancel(parent)
    tasks := make(chan privateParallelLine)
    output := make(chan privateParallelLine, privateParallelAMaxInFlight)
    s := &privateParallelPreparedStream{
        cancel: cancel, done: make(chan struct{}), results: output,
        credits: make(chan struct{}, privateParallelAMaxInFlight),
        nextOrdinal: 1, reorder: make(map[int64]privateParallelLine),
    }
    for i := 0; i < privateParallelAMaxInFlight; i++ { s.credits <- struct{}{} }
    var workers sync.WaitGroup
    workers.Add(privateParallelAPreparers + 1)

    go func() {
        defer workers.Done()
        defer close(tasks)
        var ordinal int64
        metrics, scanErr := streamCanonicalSpoolBlocks(ctx, reader,
            privateHeaderFirstBlockBytes, privateHeaderFirstMaxRecordBytes,
            func(raw []byte, kind string, family spoolDispatchFamily) error {
                // No unbounded read-ahead. A block may contain many lines;
                // only four owned raw line copies are admitted at a time.
                select {
                case <-ctx.Done(): return ctx.Err()
                case <-s.credits:
                }
                ordinal++
                line := privateParallelLine{
                    ordinal: ordinal,
                    raw: append([]byte(nil), raw...),
                    // Early dispatch metadata is immutable and is delivered
                    // along with the original signed record bytes.
                    headerKind: kind, headerFamily: family,
                }
                select {
                case <-ctx.Done(): return ctx.Err()
                case tasks <- line: return nil
                }
            })
        s.readerTime = metrics.ReadTime
        fmt.Printf("FI HEADER FIRST BLOCK STREAM records=%d bytes=%d read_calls=%d cross_block=%d reader_time=%s\n",
            metrics.Records, metrics.Bytes, metrics.ReadCalls, metrics.CrossBlockRecords, metrics.ReadTime)
        if scanErr != nil && ctx.Err() == nil {
            // The error is an ordered result as far as Next is concerned:
            // reserve a credit or its normal return would deadlock when the
            // credit channel is full. An error is NEVER silently treated as EOF.
            select {
            case <-s.credits:
            case <-ctx.Done(): return
            }
            select {
            case tasks <- privateParallelLine{ordinal: ordinal+1, readErr: fmt.Errorf("FI header-first signed spool: %w", scanErr)}:
            case <-ctx.Done():
            }
        }
    }()

    for i := 0; i < privateParallelAPreparers; i++ {
        go func() {
            defer workers.Done()
            for {
                var line privateParallelLine
                var ok bool
                select {
                case <-ctx.Done(): return
                case line, ok = <-tasks:
                }
                if !ok { return }
                if line.readErr == nil {
                    started := time.Now()
                    line.source, line.security, line.selected, line.prepareErr = prepare(
                        line.raw, line.headerKind, line.headerFamily)
                    line.prepareTime = time.Since(started)
                }
                select {
                case <-ctx.Done(): return
                case output <- line:
                }
            }
        }()
    }

    go func() {
        workers.Wait()
        close(output)
        close(s.done)
    }()
    return s, nil
}
