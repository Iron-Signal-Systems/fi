// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

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
