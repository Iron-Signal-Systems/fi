// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// A deliberately minimal pgx transaction adapter. Only CopyFrom can be called;
// other methods are unimplemented and would fail the test, not modify a DB.
type contentHashChunkCaptureTx struct {
	pgx.Tx
	calls []int
	fail  bool
}

func (tx *contentHashChunkCaptureTx) CopyFrom(_ context.Context, _ pgx.Identifier, _ []string, source pgx.CopyFromSource) (int64, error) {
	if tx.fail {
		return 0, errors.New("simulated COPY failure")
	}
	count := 0
	for source.Next() {
		values, err := source.Values()
		if err != nil {
			return 0, err
		}
		if len(values) != 8 {
			return 0, errors.New("invalid source row width")
		}
		count++
	}
	if err := source.Err(); err != nil {
		return 0, err
	}
	tx.calls = append(tx.calls, count)
	return int64(count), nil
}

func contentHashChunkTestRow(detail string) []any {
	return []any{int64(1), "Present", nil, nil, nil, nil, nil, detail}
}

func TestFIContentHashCopyChunkRowBound(t *testing.T) {
	if contentHashCopyMaxRows != 1024 || contentHashCopyMaxBytes != 2<<20 {
		t.Fatal("unexpected accepted hash COPY row/byte cap")
	}
	writer := newContentHashCopyState()
	tx := &contentHashChunkCaptureTx{}
	for n := 0; n < contentHashCopyMaxRows+1; n++ {
		if err := writer.add(context.Background(), tx, contentHashChunkTestRow("small")); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.flush(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if len(tx.calls) != 2 || tx.calls[0] != 1024 || tx.calls[1] != 1 {
		t.Fatalf("COPY chunk calls=%v, want [1024 1]", tx.calls)
	}
	if writer.copied != 1025 || writer.calls != 2 {
		t.Fatalf("rows=%d calls=%d", writer.copied, writer.calls)
	}
}

func TestFIContentHashCopyChunkByteBound(t *testing.T) {
	writer := newContentHashCopyState()
	tx := &contentHashChunkCaptureTx{}
	large := strings.Repeat("a", 4<<20)
	for n := 0; n < 2; n++ {
		if err := writer.add(context.Background(), tx, contentHashChunkTestRow(large)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.flush(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if len(tx.calls) != 2 || tx.calls[0] != 1 || tx.calls[1] != 1 {
		t.Fatalf("COPY chunk calls=%v, want [1 1]", tx.calls)
	}
}

func TestFIContentHashCopyChunkFailureDoesNotClaimRows(t *testing.T) {
	writer := newContentHashCopyState()
	tx := &contentHashChunkCaptureTx{fail: true}
	if err := writer.add(context.Background(), tx, contentHashChunkTestRow("small")); err != nil {
		t.Fatal(err)
	}
	if err := writer.flush(context.Background(), tx); err == nil {
		t.Fatal("expected COPY failure")
	}
	if writer.copied != 0 || writer.calls != 0 {
		t.Fatalf("failed COPY was counted: rows=%d calls=%d", writer.copied, writer.calls)
	}
	if len(writer.rows) != 1 {
		t.Fatalf("failed COPY lost %d buffered rows", 1-len(writer.rows))
	}
}
