// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/operation"
)

func TestFinishSupportingSourceRefreshOperationPublishesOnlyAfterDurableAppend(t *testing.T) {
	started, err := operation.Start(
		supportingSourceRefreshScopeID,
		records.OperationSupportingSourceRefresh,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Passing a directory path forces AppendFinished to fail on Windows. The
	// helper must not return an in-memory terminal record that was never made
	// durable in the lifecycle journal.
	record, err := finishSupportingSourceRefreshOperation(
		t.TempDir(),
		started,
		records.OperationComplete,
		"",
	)
	if err == nil {
		t.Fatal("expected terminal journal append failure")
	}
	if record != nil {
		t.Fatalf("undurable terminal record was published: %#v", record)
	}
}

func TestFinishSupportingSourceRefreshOperationReturnsDurableRecord(t *testing.T) {
	started, err := operation.Start(
		supportingSourceRefreshScopeID,
		records.OperationSupportingSourceRefresh,
	)
	if err != nil {
		t.Fatal(err)
	}

	journalPath := filepath.Join(t.TempDir(), "supporting-refresh-operations.jsonl")
	record, err := finishSupportingSourceRefreshOperation(
		journalPath,
		started,
		records.OperationComplete,
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if record == nil {
		t.Fatal("durable terminal record was not returned")
	}

	entries, err := operation.ReadAll(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("journal entries = %d, want 1", len(entries))
	}
	if entries[0].Event != operation.JournalFinished {
		t.Fatalf("journal event = %q, want %q", entries[0].Event, operation.JournalFinished)
	}
	if entries[0].OperationID != record.OperationID {
		t.Fatalf("journal operation_id = %q, want %q", entries[0].OperationID, record.OperationID)
	}
}

func TestSupportingSourceRefreshOperationKind(t *testing.T) {
	value := validOperationRecordForSupportingRefreshTest()
	if err := records.ValidateOperationRecord(value); err != nil {
		t.Fatal(err)
	}
}

func TestSupportingSourceRefreshLive(t *testing.T) {
	if os.Getenv("FI_LIVE_SUPPORTING_REFRESH") != "1" {
		t.Skip("set FI_LIVE_SUPPORTING_REFRESH=1 to run the live source refresh")
	}

	summary, err := writeSupportingSourceRefresh(context.Background())
	raw, marshalErr := json.MarshalIndent(summary, "", "  ")
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	t.Log(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if summary.Status != supportingSourceRefreshComplete &&
		summary.Status != supportingSourceRefreshPartial {
		t.Fatalf("refresh status = %q", summary.Status)
	}
	if summary.RecoveredOperations == nil {
		t.Fatal("refresh returned null recovered_operations")
	}
	if summary.Operation == nil {
		t.Fatal("refresh did not return an operation record")
	}
	if summary.Operation.Kind != records.OperationSupportingSourceRefresh {
		t.Fatalf("operation kind = %q", summary.Operation.Kind)
	}
	if summary.VerifiedBatches != len(summary.Batches) {
		t.Fatalf(
			"verified batches = %d, batches = %d",
			summary.VerifiedBatches,
			len(summary.Batches),
		)
	}
	if summary.SupportingSIDStatePath == "" {
		t.Fatal("refresh did not report supporting SID state path")
	}
	if summary.SupportingSIDCountAfter < summary.SupportingSIDCountBefore {
		t.Fatalf(
			"supporting SID count shrank: %d -> %d",
			summary.SupportingSIDCountBefore,
			summary.SupportingSIDCountAfter,
		)
	}
}

func validOperationRecordForSupportingRefreshTest() records.OperationRecord {
	return records.OperationRecord{
		OperationID: "op-0123456789abcdef0123456789abcdef",
		ScopeID:     supportingSourceRefreshScopeID,
		Kind:        records.OperationSupportingSourceRefresh,
		StartedAt:   "2026-08-26T17:00:00.000000000Z",
		FinishedAt:  "2026-08-26T17:00:01.000000000Z",
		Outcome:     records.OperationComplete,
	}
}
