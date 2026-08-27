// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestAppendConfiguredOperationOmitsZeroRecord(t *testing.T) {
	operations := []records.OperationRecord{}
	operations = appendConfiguredOperation(operations, records.OperationRecord{})
	if len(operations) != 0 {
		t.Fatalf("operations = %d, want 0", len(operations))
	}
}

func TestRunConfiguredOperationPreDurableStartFailureReturnsNoSummaryRecord(t *testing.T) {
	root := t.TempDir()
	stateFile := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(stateFile, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FI_STATE_DIR", stateFile)

	bodyCalled := false
	record, err := runConfiguredOperation(
		"scope-test",
		records.OperationBaseline,
		func() error {
			bodyCalled = true
			return nil
		},
	)
	if err == nil {
		t.Fatal("expected durable-start failure")
	}
	if bodyCalled {
		t.Fatal("operation body ran before Started could be durably appended")
	}
	if record.OperationID != "" {
		t.Fatalf("operation_id = %q, want empty", record.OperationID)
	}
	if got := appendConfiguredOperation(nil, record); len(got) != 0 {
		t.Fatalf("summary operations = %d, want 0", len(got))
	}
}

func TestRunConfiguredOperationBodyFailureReturnsValidFailedRecord(t *testing.T) {
	t.Setenv("FI_STATE_DIR", t.TempDir())

	record, err := runConfiguredOperation(
		"scope-test",
		records.OperationBaseline,
		func() error { return errors.New("boom") },
	)
	if err == nil {
		t.Fatal("expected body failure")
	}
	if record.OperationID == "" {
		t.Fatal("durably started operation returned empty operation ID")
	}
	if record.Outcome != records.OperationFailed {
		t.Fatalf("outcome = %q, want %q", record.Outcome, records.OperationFailed)
	}
	if err := records.ValidateOperationRecord(record); err != nil {
		t.Fatal(err)
	}
	if got := appendConfiguredOperation(nil, record); len(got) != 1 {
		t.Fatalf("summary operations = %d, want 1", len(got))
	}
}
