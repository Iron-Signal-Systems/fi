// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"errors"
	"fmt"
	"hash"
	"hash/fnv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// hashH16CaptureTx consumes the exact pgx.CopyFromSource contract; no SQL
// server, Go transaction, hash output, or source artifact is modified.
type hashH16CaptureTx struct {
	pgx.Tx
	calls []int
	digest hash.Hash64
	fail bool
}

func (tx *hashH16CaptureTx) CopyFrom(
	_ context.Context, table pgx.Identifier, cols []string, src pgx.CopyFromSource,
) (int64, error) {
	if len(table) != 2 || table[0] != "fi" || table[1] != "content_hash_observation" ||
		len(cols) != 8 || cols[0] != "source_record_id" || cols[7] != "detail" {
		return 0, errors.New("H16 attempted to change COPY destination or columns")
	}
	if tx.fail {
		return 0, errors.New("injected H16 COPY failure")
	}
	n := 0
	for src.Next() {
		row, err := src.Values()
		if err != nil {
			return 0, err
		}
		if len(row) != 8 {
			return 0, errors.New("H16 source row width changed")
		}
		// Delimit all eight values and use the SAME formatting/digest in
		// the F3 and H16 cases. Comparisons detect order/value changes.
		for _, field := range row {
			if _, err := fmt.Fprintf(tx.digest, "%T:%v\x00", field, field); err != nil {
				return 0, err
			}
		}
		n++
	}
	if err := src.Err(); err != nil {
		return 0, err
	}
	tx.calls = append(tx.calls, n)
	return int64(n), nil
}

func newH16CaptureTx() *hashH16CaptureTx {
	return &hashH16CaptureTx{digest: fnv.New64a()}
}

func h16TestRow(id int) []any {
	return []any{int64(id), "NotApplicable", nil, nil, nil, nil, nil, nil}
}

func TestPrivateHashH16IsolatedAndBounded(t *testing.T) {
	production := fileBulkLimitsFromContext(context.Background())
	if _, err := WithPrivateFileHashH16(context.Background()); err == nil {
		t.Fatal("H16 accepted production default F1")
	}
	if _, err := WithPrivateFileHashH16(nil); err == nil {
		t.Fatal("H16 accepted a nil context")
	}
	for _, name := range []string{"F1", "F2", "F4"} {
		c, err := withFixedFileBulkProfile(context.Background(), name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := WithPrivateFileHashH16(c); err == nil {
			t.Fatalf("H16 accepted non-F3 profile %s", name)
		}
	}
	f3, err := withFixedFileBulkProfile(context.Background(), "F3")
	if err != nil {
		t.Fatal(err)
	}
	original := fileBulkLimitsFromContext(f3)
	h16, err := WithPrivateFileHashH16(f3)
	if err != nil {
		t.Fatal(err)
	}
	got := fileBulkLimitsFromContext(h16)
	if got.Name != "F3H16" || got.HashMaxRows != 16384 || got.HashMaxBytes != 16<<20 {
		t.Fatalf("H16 bounded hash limits wrong: %+v", got)
	}
	withoutHash := got
	withoutHash.Name = "F3"
	withoutHash.HashMaxRows = original.HashMaxRows
	withoutHash.HashMaxBytes = original.HashMaxBytes
	if withoutHash != original {
		t.Fatalf("H16 changed non-hash F3 settings: got=%+v want=%+v", got, original)
	}
	if _, err := WithPrivateFileHashH16(h16); err == nil {
		t.Fatal("H16 allowed double application / changed known profile")
	}
	if gotBack := fileBulkLimitsFromContext(f3); gotBack != original {
		t.Fatalf("H16 mutated original F3 context: %+v", gotBack)
	}
	if gotBack := fileBulkLimitsFromContext(context.Background()); gotBack != production {
		t.Fatalf("H16 mutated production F1 defaults: %+v", gotBack)
	}
}

func TestPrivateHashH16CopyPreservesRowsAndReducesCalls(t *testing.T) {
	f3, err := withFixedFileBulkProfile(context.Background(), "F3")
	if err != nil {
		t.Fatal(err)
	}
	h16, err := WithPrivateFileHashH16(f3)
	if err != nil {
		t.Fatal(err)
	}

	run := func(ctx context.Context) (*hashH16CaptureTx, *contentHashCopyState) {
		t.Helper()
		tx := newH16CaptureTx()
		state := newContentHashCopyState()
		const records = 16385 // Cross both F3 and H16 exact row boundaries.
		for id := 1; id <= records; id++ {
			if err := state.add(ctx, tx, h16TestRow(id)); err != nil {
				t.Fatal(err)
			}
		}
		if err := state.flush(ctx, tx); err != nil {
			t.Fatal(err)
		}
		if state.copied != records || int64(len(tx.calls)) != state.calls {
			t.Fatalf("incomplete COPY or telemetry: copied=%d calls=%v", state.copied, tx.calls)
		}
		return tx, state
	}
	control, _ := run(f3)
	candidate, _ := run(h16)
	if fmt.Sprint(control.calls) != "[8192 8192 1]" {
		t.Fatalf("unexpected F3 COPY row batch boundaries: %v", control.calls)
	}
	if fmt.Sprint(candidate.calls) != "[16384 1]" {
		t.Fatalf("H16 did not reduce COPY call count as designed: %v", candidate.calls)
	}
	if control.digest.Sum64() != candidate.digest.Sum64() {
		t.Fatalf("H16 changed COPY row order or values: control=%016x candidate=%016x",
			control.digest.Sum64(), candidate.digest.Sum64())
	}
}

func TestPrivateHashH16ByteLimitAndCopyFailure(t *testing.T) {
	f3, err := withFixedFileBulkProfile(context.Background(), "F3")
	if err != nil {
		t.Fatal(err)
	}
	h16, err := WithPrivateFileHashH16(f3)
	if err != nil {
		t.Fatal(err)
	}
	// Two 6MiB rows must flush separately with F3's 8MiB bound, but
	// together under H16's 16MiB bound. Other row values are unchanged.
	payload := strings.Repeat("x", 6<<20)
	for _, tc := range []struct {
		name string
		ctx context.Context
		want string
	}{
		{"F3", f3, "[1 1]"},
		{"H16", h16, "[2]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := newContentHashCopyState()
			tx := newH16CaptureTx()
			for id := 1; id <= 2; id++ {
				row := []any{int64(id), "NotApplicable", nil, nil, nil, nil, nil, payload}
				if err := state.add(tc.ctx, tx, row); err != nil {
					t.Fatal(err)
				}
				if state.bytes > fileBulkLimitsFromContext(tc.ctx).HashMaxBytes {
					t.Fatalf("hash batch exceeded byte bound: %d", state.bytes)
				}
			}
			if err := state.flush(tc.ctx, tx); err != nil {
				t.Fatal(err)
			}
			if fmt.Sprint(tx.calls) != tc.want {
				t.Fatalf("COPY byte boundaries=%v want=%s", tx.calls, tc.want)
			}
		})
	}
	state := newContentHashCopyState()
	tx := newH16CaptureTx()
	tx.fail = true
	if err := state.add(h16, tx, h16TestRow(17)); err != nil {
		t.Fatal(err)
	}
	if err := state.flush(h16, tx); err == nil {
		t.Fatal("simulated COPY failure accepted")
	}
	if state.copied != 0 || state.calls != 0 || len(state.rows) != 1 {
		t.Fatalf("failure advanced COPY counters or discarded pending data: %+v", state)
	}
}
