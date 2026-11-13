// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Candidate A: ONLY the disposable W128/P3/F3H16 combined-buffer trial.
// Two CPU preparation workers, one signed-file reader and one original
// PostgreSQL writer. No SQL operations or source-order decisions in workers.
package recordingest

import (
    "bufio"
    "context"
    "errors"
    "fmt"
    "io"
    "sync"
    "time"
)

const (
    privateParallelAPreparers = 2
    privateParallelAMaxInFlight = 4
)

type privateParallelAKey struct{}

func WithPrivateParallelPreparationA(ctx context.Context) (context.Context, error) {
    if ctx == nil || !privateDependencyBuffersEnabled(ctx) ||
        !usePrivateSinglePassSecurity(ctx) ||
        joinedBacklogChunkRecords(ctx) != 32768 ||
        !privateH16CombinedFileProfileValid(ctx) ||
        fileBulkLimitsFromContext(ctx).Name != "F3" ||
        securityBulkLimitsFromContext(ctx).Name != "P3" {
        return nil, errors.New("FI candidate A requires private combined H16 W128/K32/P3/F3 signed-buffer context")
    }
    return context.WithValue(ctx, privateParallelAKey{}, true), nil
}

// Selection intentionally takes place before WithPrivateFileHashH16
// converts the original F3 limits into the validated F3H16 profile.
// Runtime activation MUST occur only after that conversion. Distinguish
// selection from activation so the ingest path can fail closed rather
// than silently run the historical single-preparer implementation.
func privateParallelARequested(ctx context.Context) bool {
    return ctx != nil && ctx.Value(privateParallelAKey{}) == true
}

func privateParallelAEnabled(ctx context.Context) bool {
    return privateParallelARequested(ctx) &&
        privateDependencyBuffersEnabled(ctx) &&
        usePrivateSinglePassSecurity(ctx) &&
        joinedBacklogChunkRecords(ctx) == 32768 &&
        privateH16CombinedFileProfileValid(ctx) &&
        fileBulkLimitsFromContext(ctx).Name == "F3H16" &&
        securityBulkLimitsFromContext(ctx).Name == "P3"
}

// Only the pure signed-record preparation function runs in either worker.
// This is the exact sequential order of calls from the original ingest loop:
// canonical Security fast path first; unchanged generic fallback second.
type privateParallelPrepareFunc func([]byte) (SourceRecord, securityBulkRecord, bool, error)

func privateParallelAPrepare(raw []byte) (SourceRecord, securityBulkRecord, bool, error) {
    source, security, selected, err := tryPrepareSinglePassSecurity(raw)
    if err == nil && !selected {
        source, err = prepareOwnedSourceRecord(raw)
    }
    return source, security, selected, err
}

type privateParallelLine struct {
    ordinal int64
    raw []byte
    readErr error
    readTime time.Duration
    prepareTime time.Duration
    source SourceRecord
    security securityBulkRecord
    selected bool
    prepareErr error
}

type privateParallelPreparedStream struct {
    cancel context.CancelFunc
    done chan struct{}
    results <-chan privateParallelLine
    credits chan struct{}
    nextOrdinal int64
    reorder map[int64]privateParallelLine

    // Only the original writer goroutine updates these counters.
    rows int64
    waits time.Duration
    readerTime time.Duration
    workerTime time.Duration
    reordered int64
    peakReorder int
}

// newPrivateParallelPreparedStream consumes a single immutable signed file
// through one reader, two pure workers, and a four-record credit budget.
// Credits are not returned until the ordered writer receives the record.
// Even if record 1 takes much longer than record 2, reading and preparation
// are limited to four total in-flight records; out-of-order results cannot
// grow an unbounded map or steal a source ordinal.
func newPrivateParallelPreparedStream(parent context.Context, reader *bufio.Reader, prepare privateParallelPrepareFunc) (*privateParallelPreparedStream, error) {
    if parent == nil || reader == nil || prepare == nil {
        return nil, errors.New("FI candidate A: nil reader, context, or preparer")
    }
    ctx, cancel := context.WithCancel(parent)
    tasks := make(chan privateParallelLine)
    output := make(chan privateParallelLine, privateParallelAMaxInFlight)
    s := &privateParallelPreparedStream{
        cancel: cancel, done: make(chan struct{}), results: output,
        credits: make(chan struct{}, privateParallelAMaxInFlight),
        nextOrdinal: 1, reorder: make(map[int64]privateParallelLine),
    }
    for i := 0; i < privateParallelAMaxInFlight; i++ {
        s.credits <- struct{}{}
    }

    var workers sync.WaitGroup
    workers.Add(privateParallelAPreparers + 1)
    go func() {
        defer workers.Done()
        defer close(tasks)
        var ordinal int64
        for {
            select {
            case <-ctx.Done():
                return
            case <-s.credits:
            }
            started := time.Now()
            raw, readErr := reader.ReadBytes('\n')
            elapsed := time.Since(started)
            if len(raw) == 0 && errors.Is(readErr, io.EOF) {
                // Reader reached normal EOF. No record consumed this credit.
                return
            }
            ordinal++
            line := privateParallelLine{
                ordinal: ordinal, raw: raw, readErr: readErr, readTime: elapsed,
            }
            select {
            case tasks <- line:
            case <-ctx.Done():
                return
            }
            if readErr != nil {
                return
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
                case <-ctx.Done():
                    return
                case line, ok = <-tasks:
                }
                if !ok {
                    return
                }
                // The original sequential writer checks final LF before
                // decoding. Preserve that rejection precedence exactly.
                if len(line.raw) > 0 && line.raw[len(line.raw)-1] == '\n' {
                    started := time.Now()
                    line.source, line.security, line.selected, line.prepareErr = prepare(line.raw)
                    line.prepareTime = time.Since(started)
                }
                select {
                case output <- line:
                case <-ctx.Done():
                    return
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

// Next returns strictly source-ordinal order. Nothing downstream observes
// worker completion order. A credit is returned only for a delivered result,
// bounding the number of pending raw or decoded records.
func (s *privateParallelPreparedStream) Next() (privateParallelLine, bool) {
    if line, ok := s.reorder[s.nextOrdinal]; ok {
        delete(s.reorder, s.nextOrdinal)
        s.nextOrdinal++
        s.credits <- struct{}{}
        s.record(line)
        return line, true
    }
    for {
        started := time.Now()
        line, ok := <-s.results
        s.waits += time.Since(started)
        if !ok {
            if len(s.reorder) != 0 {
                return privateParallelLine{
                    ordinal: s.nextOrdinal,
                    readErr: fmt.Errorf("FI candidate A: source preparation gap at ordinal %d", s.nextOrdinal),
                }, true
            }
            return privateParallelLine{}, false
        }
        if line.ordinal != s.nextOrdinal {
            // The admission-credit budget bounds the reorder map by 3.
            if line.ordinal < s.nextOrdinal || line.ordinal > s.nextOrdinal+privateParallelAMaxInFlight-1 {
                return privateParallelLine{
                    ordinal: s.nextOrdinal,
                    readErr: fmt.Errorf("FI candidate A: invalid preparation ordinal %d expected %d", line.ordinal, s.nextOrdinal),
                }, true
            }
            if _, exists := s.reorder[line.ordinal]; exists {
                return privateParallelLine{
                    ordinal: s.nextOrdinal,
                    readErr: errors.New("FI candidate A: duplicate preparation ordinal"),
                }, true
            }
            s.reorder[line.ordinal] = line
            s.reordered++
            if len(s.reorder) > s.peakReorder {
                s.peakReorder = len(s.reorder)
            }
            continue
        }
        s.nextOrdinal++
        s.credits <- struct{}{}
        s.record(line)
        return line, true
    }
}

func (s *privateParallelPreparedStream) record(line privateParallelLine) {
    s.rows++
    s.readerTime += line.readTime
    s.workerTime += line.prepareTime
}

// Close cancels reading and all workers, then joins every goroutine BEFORE
// the original ingest caller closes the underlying signed batch file.
// This also works on malformed input, SQL failures and W128 rollback.
func (s *privateParallelPreparedStream) Close() {
    if s == nil {
        return
    }
    s.cancel()
    <-s.done
}
