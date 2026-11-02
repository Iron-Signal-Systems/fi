package recordingest

import (
    "context"
    "testing"
)

// A chunk counts independent pending_source_record SQL COPY rows, not
// signed source batches or an outer recovery transaction boundary.
func TestJoinedSourceChunkLimitsAndPartition(t *testing.T) {
    const window = 131072
    tests := []struct {
        rows int
        expected []int
    }{
        {32768, []int{32768, 32768, 32768, 32768}},
        {65536, []int{65536, 65536}},
        {98304, []int{98304, 32768}},
        {131072, []int{131072}},
    }
    for _, tt := range tests {
        ctx, err := WithBacklogJoinedSourceChunkRecords(context.Background(), tt.rows)
        if err != nil {
            t.Fatalf("configure %d: %v", tt.rows, err)
        }
        if got := joinedBacklogChunkRecords(ctx); got != tt.rows {
            t.Fatalf("configured %d: got %d", tt.rows, got)
        }
        var chunks []int
        pending := 0
        for i := 0; i < window; i++ {
            pending++
            if shouldFlushJoinedSourceChunk(pending, joinedBacklogChunkRecords(ctx)) {
                chunks = append(chunks, pending)
                pending = 0
            }
        }
        if pending != 0 {
            chunks = append(chunks, pending)
        }
        if len(chunks) != len(tt.expected) {
            t.Fatalf("chunk %d: got %v, want %v", tt.rows, chunks, tt.expected)
        }
        for i := range tt.expected {
            if chunks[i] != tt.expected[i] {
                t.Fatalf("chunk %d: got %v, want %v", tt.rows, chunks, tt.expected)
            }
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
    if shouldFlushJoinedSourceChunk(1, 0) || shouldFlushJoinedSourceChunk(32767, 32768) {
        t.Fatal("premature joined source COPY flush")
    }
    if !shouldFlushJoinedSourceChunk(32768, 32768) {
        t.Fatal("joined source COPY limit not enforced")
    }
}
