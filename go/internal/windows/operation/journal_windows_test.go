// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package operation

import (
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestAppendReadAllRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operations.jsonl")
	first := testRecord("op-0123456789abcdef0123456789abcdef", records.OperationUSNRead)
	second := testRecord("op-fedcba9876543210fedcba9876543210", records.OperationReObservation)

	if err := Append(path, first); err != nil {
		t.Fatal(err)
	}
	if err := Append(path, second); err != nil {
		t.Fatal(err)
	}

	values, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 {
		t.Fatalf("got %d records, want 2", len(values))
	}
	if values[0].OperationID != first.OperationID || values[1].OperationID != second.OperationID {
		t.Fatal("operation journal order changed")
	}
}

func testRecord(id string, kind records.OperationKind) records.OperationRecord {
	return records.OperationRecord{
		OperationID: id,
		ScopeID:     "manual-test",
		Kind:        kind,
		StartedAt:   "2026-08-22T17:20:00.000000000Z",
		FinishedAt:  "2026-08-22T17:20:01.000000000Z",
		Outcome:     records.OperationComplete,
	}
}
