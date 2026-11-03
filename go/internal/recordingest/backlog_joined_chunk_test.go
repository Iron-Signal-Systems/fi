package recordingest

import (
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

// Each COPY group is an ordered sequence of intact authenticated 8,192-row
// source batches. SQL row count is nominal; source batches are never split.
func TestJoinedSourceChunkLimitsAndWholeBatchPartition(t *testing.T) {
    const (
        windowRecords = 131072
        signedBatchRecords = 8192
    )
    tests := []struct {
        limit int
        expected []int
    }{
        {32768, []int{32768, 32768, 32768, 32768}},
        {65536, []int{65536, 65536}},
        {98304, []int{98304, 32768}},
        {131072, []int{131072}},
    }
    for _, tt := range tests {
        ctx, err := WithBacklogJoinedSourceChunkRecords(context.Background(), tt.limit)
        if err != nil {
            t.Fatalf("configure %d: %v", tt.limit, err)
        }
        if got := joinedBacklogChunkRecords(ctx); got != tt.limit {
            t.Fatalf("configured %d: got %d", tt.limit, got)
        }
        chunks := make([]int, 0, 4)
        pending := 0
        for i := 0; i < windowRecords/signedBatchRecords; i++ {
            if shouldFlushJoinedSourceChunk(pending, signedBatchRecords, joinedBacklogChunkRecords(ctx)) {
                chunks = append(chunks, pending)
                pending = 0
            }
            pending += signedBatchRecords
            if pending > tt.limit {
                t.Fatalf("chunk %d: signed batch broke buffer limit", tt.limit)
            }
        }
        if pending > 0 {
            chunks = append(chunks, pending)
        }
        if len(chunks) != len(tt.expected) {
            t.Fatalf("chunk %d: got %v, want %v", tt.limit, chunks, tt.expected)
        }
        for i := range tt.expected {
            if chunks[i] != tt.expected[i] {
                t.Fatalf("chunk %d: got %v, want %v", tt.limit, chunks, tt.expected)
            }
        }
    }
}

func TestJoinedSourceChunkUnevenSignedBatches(t *testing.T) {
    const chunk = 32768
    batches := []int{8000, 9000, 12000, 8000, 100, 32768, 1}
    var chunks []int
    pending := 0
    for _, count := range batches {
        if shouldFlushJoinedSourceChunk(pending, count, chunk) {
            chunks = append(chunks, pending)
            pending = 0
        }
        pending += count
        if pending > chunk {
            t.Fatalf("buffer exceeded chunk limit %d", pending)
        }
    }
    if pending > 0 {
        chunks = append(chunks, pending)
    }
    expected := []int{29000, 8100, 32768, 1}
    if len(chunks) != len(expected) {
        t.Fatalf("got %v want %v", chunks, expected)
    }
    for i := range expected {
        if chunks[i] != expected[i] {
            t.Fatalf("got %v want %v", chunks, expected)
        }
    }
}

func TestJoinedSourceChunkRejectsInvalidInputs(t *testing.T) {
    if got := joinedBacklogChunkRecords(context.Background()); got != backlogDefaultJoinedSourceChunkRecords {
        t.Fatalf("legacy default changed: %d", got)
    }
    for _, count := range []int{-1, 0, 8192, 16384, 32767, 131073, 262144} {
        if _, err := WithBacklogJoinedSourceChunkRecords(context.Background(), count); err == nil {
            t.Fatalf("invalid count %d allowed", count)
        }
    }
    if _, err := WithBacklogJoinedSourceChunkRecords(nil, 32768); err == nil {
        t.Fatal("nil context accepted")
    }
    if shouldFlushJoinedSourceChunk(0, 8192, 32768) ||
        shouldFlushJoinedSourceChunk(8192, 8192, 32768) {
        t.Fatal("premature joined source COPY flush")
    }
    if !shouldFlushJoinedSourceChunk(24576, 8193, 32768) {
        t.Fatal("joined source COPY not flushed before overflowing signed batch")
    }
    s := &joinedBacklogSource{chunkRows:32768}
    if err := s.beginBatch(context.Background(), 32769); err == nil {
        t.Fatal("oversized signed batch accepted")
    }
}

func TestJoinedSourcePreparedDigestAndCrossBatchIdentity(t *testing.T) {
    ctx := context.Background()
    at := time.Date(2026, 11, 3, 12, 34, 56, 0, time.UTC)
    var digest [32]byte
    for i := range digest { digest[i] = byte(i + 1) }
    p := SourceRecord{
        Record: spool.Record{
            Version: SpoolRecordVersion, RecordKind: "WindowsSecurityEvent",
            ScopeID: "test-scope", WrittenAt: "2026-11-03T12:34:56.000000000Z",
        },
        RecordBytes: 512, RecordSHA256: hex.EncodeToString(digest[:]),
        WrittenAtUTC: at,
    }
    s := &joinedBacklogSource{
        descriptor: BacklogCheckpointDescriptor{StartBatch: 0, EndBatch: 3},
        batchIndex: 1, chunkRows: 32768,
        digest: sha256.New(), families: make(map[string]uint64),
    }
    sourceBytes := append([]byte(nil), digest[:]...)
    if err := s.addPrepared(ctx, 1, p, sourceBytes); err != nil { t.Fatal(err) }
    sourceBytes[0] ^= 0xff // The COPY buffer must own its source digest bytes.
    if s.rows[0].digest != digest { t.Fatal("source digest aliased caller buffer") }
    if s.rows[0].batchIndex != 1 || s.rows[0].ordinal != 1 ||
       s.rows[0].version != p.Record.Version || s.rows[0].recordKind != p.Record.RecordKind ||
       s.rows[0].scopeID != p.Record.ScopeID || !s.rows[0].writtenAtUTC.Equal(at) ||
       s.rows[0].writtenAtOriginal != p.Record.WrittenAt || s.rows[0].recordBytes != 512 {
        t.Fatal("typed buffer changed source row identity or COPY columns")
    }
    s.batchIndex = 2
    if err := s.addPrepared(ctx, 1, p, digest[:]); err != nil { t.Fatal(err) }
    if len(s.rows) != 2 || s.rows[1].batchIndex != 2 || s.rows[1].ordinal != 1 {
        t.Fatal("cross-signed-batch ordinals or identity changed")
    }
    expected := sha256.New()
    backlogHashSourceRow(expected, 1, 1, p.Record.Version, p.Record.RecordKind,
        p.Record.ScopeID, p.Record.WrittenAt, p.RecordBytes, digest[:])
    backlogHashSourceRow(expected, 2, 1, p.Record.Version, p.Record.RecordKind,
        p.Record.ScopeID, p.Record.WrittenAt, p.RecordBytes, digest[:])
    if !bytes.Equal(s.digest.Sum(nil), expected.Sum(nil)) {
        t.Fatal("joined source digest changed after avoiding duplicate decode")
    }
    if s.records != 2 || s.bytes != 1024 || s.families["WindowsSecurityEvent"] != 2 {
        t.Fatal("joined source counters changed")
    }
    if err := s.addPrepared(ctx, 2, p, digest[:31]); err == nil {
        t.Fatal("short digest accepted")
    }
    if err := s.add(ctx, 2, SourceRecord{RecordSHA256: "invalid"}); err == nil {
        t.Fatal("legacy direct-add accepted invalid source hex digest")
    }
}
