// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Tests the ACTIVE ingestSourceBatch dispatch helper and SQL identity/COPY
// constraints, not an unconnected mock buffering algorithm.
package recordingest

import (
    "bytes"
    "context"
    "errors"
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/jackc/pgx/v5"
)

func privateMixedTestContext(t *testing.T) context.Context {
    t.Helper()
    ctx := WithPrivateSecurityFieldPartitions(context.Background())
    var err error
    ctx, err = withFixedSecurityBulkProfile(ctx, "P3")
    if err != nil { t.Fatal(err) }
    ctx, err = withFixedFileBulkProfile(ctx, "F3")
    if err != nil { t.Fatal(err) }
    ctx, err = WithBacklogJoinedSourceChunkRecords(ctx, 32768)
    if err != nil { t.Fatal(err) }
    ctx, err = WithPrivateMixedFamilyBuffers(ctx)
    if err != nil { t.Fatal(err) }
    ctx = context.WithValue(ctx, backlogTypedChunkContextKey{},
        backlogTypedChunkDirective{state: &backlogTypedChunkState{fileBulk: newFileObservationBulkState()}})
    if !privateMixedFamilyBuffersEnabled(ctx) { t.Fatal("mixed buffer context not enabled") }
    return ctx
}

func TestPrivateMixedFamilyBuffersFailClosed(t *testing.T) {
    if _, err := WithPrivateMixedFamilyBuffers(nil); err == nil {
        t.Fatal("nil context allowed")
    }
    if _, err := WithPrivateMixedFamilyBuffers(context.Background()); err == nil {
        t.Fatal("ordinary ingestion could enable mixed buffers")
    }
    ctx := privateMixedTestContext(t)
    if privateMixedFamilyBuffersEnabled(context.Background()) {
        t.Fatal("ordinary ingestion unexpectedly enabled")
    }
    // A caller cannot enable mixed buffering merely by setting the private
    // marker: it must also run inside an active, bounded K32 chunk.
    noChunk := context.WithValue(ctx, backlogTypedChunkContextKey{}, backlogTypedChunkDirective{})
    if privateMixedFamilyBuffersEnabled(noChunk) {
        t.Fatal("mixed buffering without valid K32 state")
    }
}

func TestPrivateMixedFamilyDispatchAndUSNBarriers(t *testing.T) {
    mixed := privateMixedTestContext(t)
    normal := context.Background()
    cases := []struct {
        kind string
        baseline, candidate securityFileFlushDecision
    }{
        {"WindowsSecurityEvent",
            securityFileFlushDecision{files: true}, securityFileFlushDecision{}},
        {"FileObservation",
            securityFileFlushDecision{security: true}, securityFileFlushDecision{}},
        {"USNObjectObservation",
            securityFileFlushDecision{security: true}, securityFileFlushDecision{}},
        {"WindowsSecurityCoverage",
            securityFileFlushDecision{security: true, files: true},
            securityFileFlushDecision{security: true, files: true}},
        {"USNReadBoundary",
            securityFileFlushDecision{security: true, files: true},
            securityFileFlushDecision{security: true, files: true}},
        {"OtherObservation",
            securityFileFlushDecision{security: true, files: true},
            securityFileFlushDecision{security: true, files: true}},
    }
    for _, tc := range cases {
        t.Run(tc.kind, func(t *testing.T) {
            if got := securityFileFlushBeforeKind(normal, tc.kind); got != tc.baseline {
                t.Fatalf("ordinary flush changed: got=%+v want=%+v", got, tc.baseline)
            }
            if got := securityFileFlushBeforeKind(mixed, tc.kind); got != tc.candidate {
                t.Fatalf("private mixed flush wrong: got=%+v want=%+v", got, tc.candidate)
            }
        })
    }
}

// Counting nonempty flushes through the same dispatch helper called by
// ingestSourceBatch proves why interleaved records generate fewer COPY calls.
// Limits/size flushes and the K32 finish remain owned by the real ingester.
func mixedCopyFlushCounts(ctx context.Context, kinds []string) (security, files int) {
    pendingSecurity, pendingFiles := 0, 0
    for _, kind := range kinds {
        d := securityFileFlushBeforeKind(ctx, kind)
        if d.security && pendingSecurity > 0 { security++; pendingSecurity = 0 }
        if d.files && pendingFiles > 0 { files++; pendingFiles = 0 }
        switch kind {
        case "WindowsSecurityEvent":
            pendingSecurity++
        case "FileObservation", "USNObjectObservation":
            pendingFiles++
        }
    }
    if pendingSecurity > 0 { security++ }
    if pendingFiles > 0 { files++ }
    return security, files
}

func TestPrivateMixedBuffersReduceInterleavedPartialFlushes(t *testing.T) {
    kinds := []string{"WindowsSecurityEvent", "FileObservation",
        "WindowsSecurityEvent", "FileObservation", "WindowsSecurityEvent"}
    a, b := mixedCopyFlushCounts(context.Background(), kinds)
    if a != 3 || b != 2 {
        t.Fatalf("baseline COPY count unexpected: Security=%d File=%d", a, b)
    }
    a, b = mixedCopyFlushCounts(privateMixedTestContext(t), kinds)
    if a != 1 || b != 1 {
        t.Fatalf("independent COPY count unexpected: Security=%d File=%d", a, b)
    }
    // An USN capture boundary still forces all pending families to flush.
    a, b = mixedCopyFlushCounts(privateMixedTestContext(t),
        []string{"WindowsSecurityEvent", "FileObservation", "USNReadBoundary",
            "FileObservation", "WindowsSecurityEvent"})
    if a != 2 || b != 2 {
        t.Fatalf("USN boundary did not fence buffers: Security=%d File=%d", a, b)
    }
}

func TestMixedBulkSourceOrdinalSelection(t *testing.T) {
    cases := []struct {
        name string
        batches, ordinals []int64
        contiguous bool
    }{
        {"contiguous", []int64{41,41,41}, []int64{1,2,3}, true},
        {"interleaved-file-gap", []int64{41,41,41}, []int64{1,3,5}, false},
        {"interleaved-security-gap", []int64{41,41}, []int64{2,4}, false},
        {"different-batches", []int64{41,42}, []int64{9,1}, false},
        {"duplicate", []int64{41,41}, []int64{3,3}, false},
        {"reversed", []int64{41,41}, []int64{4,3}, false},
        {"empty", nil, nil, false},
    }
    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            if got := bulkSourceIDsAreContiguousSingleBatch(tc.batches, tc.ordinals); got != tc.contiguous {
                t.Fatalf("contiguous=%t want=%t", got, tc.contiguous)
            }
        })
    }
}

type mixedBulkQueryProbeTx struct {
    pgx.Tx
    query string
}
func (p *mixedBulkQueryProbeTx) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
    p.query = sql
    return nil, errors.New("FI query probe")
}

func TestMixedBulkSourceIDLookupUsesExactKeysWhenSparse(t *testing.T) {
    for _, tc := range []struct {
        batches, ordinals []int64
        wantFragment string
    }{
        {[]int64{41,41}, []int64{2,4}, "FROM unnest("},
        {[]int64{41,42}, []int64{5,1}, "FROM unnest("},
        {[]int64{41,41}, []int64{2,3}, "BETWEEN $2 AND $3"},
    } {
        tx := &mixedBulkQueryProbeTx{}
        _, err := lookupBulkSourceRecordIDs(context.Background(), tx, tc.batches, tc.ordinals)
        if err == nil || !strings.Contains(tx.query, tc.wantFragment) {
            t.Fatalf("wrong source ID SQL lookup (%s): sql=%q err=%v", tc.wantFragment, tx.query, err)
        }
    }
}

type mixedFileCopyProbeTx struct {
    pgx.Tx
    called bool
}
func (p *mixedFileCopyProbeTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
    p.called = true
    return 0, errors.New("FI COPY probe")
}

func TestPrivateMixedFileCopyAcceptsStrictlyIncreasingSparseOrdinals(t *testing.T) {
    item := func(n int64) fileSourceBulkRecord {
        return fileSourceBulkRecord{
            ordinal: n,
            digest: bytes.Repeat([]byte{0x54}, 32),
            prepared: SourceRecord{Record: spool.Record{RecordKind: "FileObservation"}, RecordBytes: 123},
        }
    }
    sparse := []fileSourceBulkRecord{item(1), item(3), item(5)}
    baselineTx := &mixedFileCopyProbeTx{}
    if err := copyFileSourceBulk(context.Background(), baselineTx, 41, sparse, &ingestStageProfile{}); err == nil || baselineTx.called {
        t.Fatal("ordinary File source COPY unexpectedly accepted a sparse ordinal range")
    }
    mixedTx := &mixedFileCopyProbeTx{}
    if err := copyFileSourceBulk(privateMixedTestContext(t), mixedTx, 41, sparse, &ingestStageProfile{}); err == nil || !mixedTx.called {
        t.Fatal("private mixed File source COPY failed to reach SQL with strictly increasing ordinals")
    }
    duplicate := []fileSourceBulkRecord{item(1), item(1)}
    invalidTx := &mixedFileCopyProbeTx{}
    if err := copyFileSourceBulk(privateMixedTestContext(t), invalidTx, 41, duplicate, &ingestStageProfile{}); err == nil || invalidTx.called {
        t.Fatal("private mixed COPY admitted duplicate ordinals")
    }
}
