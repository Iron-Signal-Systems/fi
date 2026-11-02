package recordingest

import (
    "context"
    "testing"
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
