// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestIngestCopyProfileRecordsAndSorts(t *testing.T) {
	m := newIngestCopyMetrics()
	m.record(pgx.Identifier{"fi", "file_observation"}, 100, 350*time.Millisecond, nil)
	m.record(pgx.Identifier{"fi", "file_observation"}, 50, 650*time.Millisecond, nil)
	m.record(pgx.Identifier{"fi", "source_record"}, 10, 120*time.Millisecond, nil)
	m.record(pgx.Identifier{"fi", "source_record"}, 0, time.Second, errors.New("fixture COPY failure"))
	if got := m.top3(); got != "fi.source_record:1.12s:2,fi.file_observation:1s:2" {
		t.Fatalf("unexpected top three: %q", got)
	}
	var output bytes.Buffer
	m.report(&output, "source-test", "generation-test", "uncommitted")
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "table=fi.source_record") ||
		!strings.Contains(lines[0], "rows_reported=10") ||
		!strings.Contains(lines[0], "errors=1") ||
		!strings.Contains(lines[0], "ge_1s=1") ||
		!strings.Contains(lines[1], "table=fi.file_observation") ||
		!strings.Contains(lines[1], "rows_reported=150") ||
		!strings.Contains(lines[1], "ge_500ms=1") {
		t.Fatalf("incorrect deterministic profile: %s", output.String())
	}
}

func TestIngestCopyProfileBoundsAndNegativeTime(t *testing.T) {
	m := newIngestCopyMetrics()
	m.record(nil, -2, -time.Second, nil)
	if m.tables[0].table != "_invalid_identifier" || m.tables[0].rows != 0 || m.tables[0].min != 0 {
		t.Fatalf("invalid input improperly recorded: %+v", m.tables[0])
	}
	for i := 0; i < ingestCopyTableLimit+5; i++ {
		m.record(pgx.Identifier{"fi", "table_" + string(rune(i+65))}, 1, time.Millisecond, nil)
	}
	if m.used != ingestCopyTableLimit || m.overflow.calls != 6 {
		// One reserved slot was taken by the deliberately invalid identifier.
		t.Fatalf("unbounded table slots: used=%d overflow=%d", m.used, m.overflow.calls)
	}
	var out bytes.Buffer
	m.report(&out, "s", "g", "accepted")
	if !strings.Contains(out.String(), "table=_overflow") {
		t.Fatal("overflow was not reported")
	}
}

func TestIngestCopyProfileEmpty(t *testing.T) {
	m := newIngestCopyMetrics()
	if m.top3() != "none" {
		t.Fatal("empty profile should have no top tables")
	}
	var out bytes.Buffer
	m.report(&out, "s", "g", "accepted")
	if out.Len() != 0 {
		t.Fatalf("empty profile emitted output: %q", out.String())
	}
}

// This is an interface-level acceptance test: the wrapper must forward the
// exact context, table, columns and row-source object, exactly once, and
// preserve both the returned count and the original error.
type copyProfileFakeTx struct {
	pgx.Tx
	calls         int
	expectContext context.Context
	expectSource  pgx.CopyFromSource
	expectColumns []string
	responseRows  int64
	responseErr   error
}

func (tx *copyProfileFakeTx) CopyFrom(ctx context.Context, table pgx.Identifier,
	columns []string, rows pgx.CopyFromSource) (int64, error) {
	tx.calls++
	if ctx != tx.expectContext || len(table) != 2 || table[0] != "fi" ||
		table[1] != "source_record" || rows != tx.expectSource ||
		len(columns) != len(tx.expectColumns) || columns[0] != tx.expectColumns[0] {
		panic("CopyFrom was invoked with modified arguments")
	}
	return tx.responseRows, tx.responseErr
}

func TestIngestCopyProfileTransactionPassThrough(t *testing.T) {
	ctx := context.Background()
	original := &copyProfileFakeTx{expectContext: ctx, expectColumns: []string{"source_record_id"}, responseRows: 17}
	metrics := newIngestCopyMetrics()
	wrapped := &profiledIngestTx{Tx: original, metrics: metrics}
	rows, err := wrapped.CopyFrom(ctx, pgx.Identifier{"fi", "source_record"}, []string{"source_record_id"}, nil)
	if err != nil || rows != 17 || original.calls != 1 || metrics.tables[0].rows != 17 {
		t.Fatalf("delegation changed: rows=%d err=%v calls=%d observed=%+v", rows, err, original.calls, metrics.tables[0])
	}
	failure := errors.New("expected failure")
	original.responseErr = failure
	rows, err = wrapped.CopyFrom(ctx, pgx.Identifier{"fi", "source_record"}, []string{"source_record_id"}, nil)
	if err != failure || original.calls != 2 || metrics.tables[0].failed != 1 || metrics.tables[0].rows != 17 {
		t.Fatalf("error delegation changed: rows=%d err=%v calls=%d observed=%+v", rows, err, original.calls, metrics.tables[0])
	}
}
