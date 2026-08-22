// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package resourcejournal

import (
	"path/filepath"
	"strconv"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestStartFinishWritesSampleAndSummary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resources.jsonl")
	tracker, err := Start(
		path,
		"op-0123456789abcdef0123456789abcdef",
		"manual-test",
		records.OperationUSNRead,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Finish(); err != nil {
		t.Fatal(err)
	}

	values, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 2 {
		t.Fatalf("got %d resource records, want 2", len(values))
	}
	if values[0].RecordKind != ResourceSample {
		t.Fatalf("first record kind = %q, want %q", values[0].RecordKind, ResourceSample)
	}
	if values[1].RecordKind != ResourceSummary {
		t.Fatalf("second record kind = %q, want %q", values[1].RecordKind, ResourceSummary)
	}
	if values[0].OperationID != values[1].OperationID {
		t.Fatal("resource records do not share operation id")
	}
	if values[1].PeakWorkingSetBytes == "0" {
		t.Fatal("summary peak working set is zero")
	}
}

func TestResourceCountersDoNotMoveBackwardWithinOperation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resources.jsonl")
	tracker, err := Start(
		path,
		"op-fedcba9876543210fedcba9876543210",
		"manual-test",
		records.OperationReObservation,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Finish(); err != nil {
		t.Fatal(err)
	}

	values, err := ReadAll(path)
	if err != nil {
		t.Fatal(err)
	}
	summary := values[len(values)-1]
	for name, value := range map[string]string{
		"cpu":              summary.CPU100Nanoseconds,
		"read_operations":  summary.ReadOperations,
		"write_operations": summary.WriteOperations,
		"other_operations": summary.OtherOperations,
	} {
		if _, err := strconv.ParseUint(value, 10, 64); err != nil {
			t.Fatalf("%s is not an unsigned integer: %q", name, value)
		}
	}
}

func TestDeltaSaturatesAtZero(t *testing.T) {
	if got := delta(4, 5); got != 0 {
		t.Fatalf("delta(4, 5) = %d, want 0", got)
	}
	if got := delta(9, 5); got != 4 {
		t.Fatalf("delta(9, 5) = %d, want 4", got)
	}
}
