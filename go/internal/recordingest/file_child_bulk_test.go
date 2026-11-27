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

type fileChildBulkTestTx struct {
	pgx.Tx
	calls   []int
	tables  []string
	failAt  int
	shortAt int
}

func (tx *fileChildBulkTestTx) CopyFrom(_ context.Context, table pgx.Identifier, cols []string, src pgx.CopyFromSource) (int64, error) {
	if len(table) != 2 || table[0] != "fi" || len(cols) == 0 {
		return 0, errors.New("bad FI COPY table or columns")
	}
	tx.tables = append(tx.tables, table[1])
	count := 0
	for src.Next() {
		vals, err := src.Values()
		if err != nil {
			return 0, err
		}
		if len(vals) != len(cols) {
			return 0, errors.New("column count mismatch")
		}
		count++
	}
	if err := src.Err(); err != nil {
		return 0, err
	}
	tx.calls = append(tx.calls, count)
	if tx.failAt > 0 && len(tx.calls) == tx.failAt {
		return 0, errors.New("injected copy failure")
	}
	if tx.shortAt > 0 && len(tx.calls) == tx.shortAt {
		return int64(count - 1), nil
	}
	return int64(count), nil
}

func TestFileChildBulkCopiesBoundedAndOrdered(t *testing.T) {
	tx := &fileChildBulkTestTx{}
	table := fileChildBulkTable{name: "stream_observation", columns: []string{"source_record_id"}}
	for i := 0; i < 2051; i++ {
		table.rows = append(table.rows, []any{int64(i + 1)})
	}
	if err := table.copy(context.Background(), tx); err != nil {
		t.Fatal(err)
	}
	if len(tx.calls) != 3 || tx.calls[0] != 1024 || tx.calls[1] != 1024 || tx.calls[2] != 3 {
		t.Fatalf("unbounded or incomplete child COPY chunks: %#v", tx.calls)
	}
	for _, name := range tx.tables {
		if name != "stream_observation" {
			t.Fatalf("unexpected table %s", name)
		}
	}
}

func TestFileChildBulkCopyFailureFailsClosed(t *testing.T) {
	table := fileChildBulkTable{name: "reparse_observation", columns: []string{"source_record_id"}, rows: [][]any{{1}, {2}}}
	if err := table.copy(context.Background(), &fileChildBulkTestTx{failAt: 1}); err == nil || !strings.Contains(err.Error(), "injected copy failure") {
		t.Fatalf("COPY failure not propagated: %v", err)
	}
	if err := table.copy(context.Background(), &fileChildBulkTestTx{shortAt: 1}); err == nil || !strings.Contains(err.Error(), "copied 1 of 2") {
		t.Fatalf("COPY short count not rejected: %v", err)
	}
	if err := table.copy(context.Background(), nil); err == nil {
		t.Fatal("accepted nil transaction")
	}
}

func TestFileChildBulkTableSchema(t *testing.T) {
	tables := newFileChildBulkTables()
	candidates := []fileChildBulkTable{tables.prefix, tables.reparse, tables.inventory, tables.streams, tables.security, tables.sacl, tables.warnings}
	seen := map[string]bool{}
	for _, table := range candidates {
		if seen[table.name] || len(table.columns) == 0 || table.columns[0] != "source_record_id" {
			t.Fatalf("invalid child table definition: %s", table.name)
		}
		seen[table.name] = true
	}
	if len(seen) != 7 {
		t.Fatalf("got %d tables", len(seen))
	}
}
