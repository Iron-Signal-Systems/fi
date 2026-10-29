// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Use a pgx.Tx stub: the test covers COPY-call telemetry without a database.
type hashCopyLatencyTx struct {
	pgx.Tx
	calls int
	fail  bool
}

func (tx *hashCopyLatencyTx) CopyFrom(
	_ context.Context, table pgx.Identifier, columns []string,
	source pgx.CopyFromSource,
) (int64, error) {
	tx.calls++
	if len(table) != 2 || table[0] != "fi" || table[1] != "content_hash_observation" ||
		len(columns) != 8 {
		return 0, errors.New("incorrect hash COPY target")
	}
	if tx.fail {
		return 0, errors.New("simulated COPY failure")
	}
	var rows int64
	for source.Next() {
		if _, err := source.Values(); err != nil {
			return 0, err
		}
		rows++
	}
	return rows, source.Err()
}

func TestHashCopyLatencyCountsCallsNotRows(t *testing.T) {
	tx := &hashCopyLatencyTx{}
	state := newContentHashCopyState()
	row := []any{int64(1), "NotApplicable", nil, nil, nil, nil, nil, nil}
	if err := state.copyRows(context.Background(), tx, [][]any{row, row}); err != nil {
		t.Fatal(err)
	}
	if err := state.copyRows(context.Background(), tx, [][]any{row}); err != nil {
		t.Fatal(err)
	}
	if tx.calls != 2 || state.calls != 2 || state.copied != 3 ||
		state.latency.Calls != 2 || state.latency.Min > state.latency.Max {
		t.Fatalf("incorrect COPY telemetry: calls=%d state=%+v", tx.calls, state)
	}
}

func TestHashCopyLatencyRecordsFailedCall(t *testing.T) {
	tx := &hashCopyLatencyTx{fail: true}
	state := newContentHashCopyState()
	row := []any{int64(1), "NotApplicable", nil, nil, nil, nil, nil, nil}
	if err := state.copyRows(context.Background(), tx, [][]any{row}); err == nil {
		t.Fatal("simulated COPY failure was accepted")
	}
	if state.latency.Calls != 1 || state.calls != 0 || state.copied != 0 {
		t.Fatalf("failed COPY incorrectly counted as committed: %+v", state)
	}
}
