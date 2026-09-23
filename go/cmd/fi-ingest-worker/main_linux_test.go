// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationready"
	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

func TestProcessPlanRetiresAcceptedReadyMarkerWithoutDatabaseWork(
	t *testing.T,
) {
	readyRoot := t.TempDir()
	name := "generation-0123456789abcdef.record.json"
	if _, err := generationready.Publish(readyRoot, name); err != nil {
		t.Fatal(err)
	}

	plan := recordingest.ReconcilePlan{
		Accepted:   1,
		Discovered: 1,
		Items: []recordingest.ReconcilePlanItem{
			{
				Candidate: recordingest.RecordedReceiptCandidate{
					Path: filepath.Join("/recorded", name),
				},
				State: recordingest.ReconcileStateAccepted,
			},
		},
	}

	var attempts uint64
	if err := processPlan(
		context.Background(),
		workerConfig{ReadyRoot: readyRoot},
		postgresConnection{},
		plan,
		true,
		&attempts,
	); err != nil {
		t.Fatal(err)
	}

	names, err := generationready.ReadReceiptNames(readyRoot, 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 0 {
		t.Fatalf("ready names after accepted retirement = %#v, want empty", names)
	}
	if attempts != 0 {
		t.Fatalf("attempts = %d, want 0", attempts)
	}
}

func TestReadyPlanEmptyQueueNeedsNoDatabaseConnection(
	t *testing.T,
) {
	plan, markers, err := readyPlan(
		context.Background(),
		workerConfig{
			ReadyBatchSize: 64,
			ReadyRoot:      t.TempDir(),
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if markers != 0 || plan.Discovered != 0 || len(plan.Items) != 0 {
		t.Fatalf(
			"empty ready plan markers=%d plan=%#v, want zero",
			markers,
			plan,
		)
	}
}

func TestSelectPendingSkipsAcceptedAndJournalDeferred(t *testing.T) {
	now := time.Date(
		2026,
		time.September,
		20,
		16,
		0,
		0,
		0,
		time.UTC,
	)

	plan := recordingest.ReconcilePlan{
		Items: []recordingest.ReconcilePlanItem{
			{
				Candidate: recordingest.RecordedReceiptCandidate{
					SourceID:     "source-1",
					GenerationID: "generation-a",
				},
				State: recordingest.ReconcileStateAccepted,
			},
			{
				Candidate: recordingest.RecordedReceiptCandidate{
					SourceID:     "source-1",
					GenerationID: "generation-b",
				},
				State: recordingest.ReconcileStatePending,
			},
			{
				Candidate: recordingest.RecordedReceiptCandidate{
					SourceID:     "source-1",
					GenerationID: "generation-c",
				},
				State: recordingest.ReconcileStatePending,
			},
		},
		Pending: 2,
	}

	rejectionTimes := map[string]time.Time{
		"generation-b": now.Add(-5 * time.Minute),
	}

	got, deferredCount, err :=
		selectPending(
			plan,
			now,
			rejectionTimes,
			15*time.Minute,
		)
	if err != nil {
		t.Fatalf(
			"selectPending() error = %v",
			err,
		)
	}

	if deferredCount != 1 {
		t.Fatalf(
			"deferredCount = %d, want 1",
			deferredCount,
		)
	}

	if len(got) != 1 {
		t.Fatalf(
			"pending count = %d, want 1",
			len(got),
		)
	}

	if got[0].Candidate.GenerationID !=
		"generation-c" {
		t.Fatalf(
			"GenerationID = %q, want generation-c",
			got[0].Candidate.GenerationID,
		)
	}
}

func TestPendingGenerationIDsReturnsPendingOnly(t *testing.T) {
	plan := recordingest.ReconcilePlan{
		Items: []recordingest.ReconcilePlanItem{
			{
				Candidate: recordingest.RecordedReceiptCandidate{
					GenerationID: "generation-a",
				},
				State: recordingest.ReconcileStateAccepted,
			},
			{
				Candidate: recordingest.RecordedReceiptCandidate{
					GenerationID: "generation-b",
				},
				State: recordingest.ReconcileStatePending,
			},
			{
				Candidate: recordingest.RecordedReceiptCandidate{
					GenerationID: "generation-c",
				},
				State: recordingest.ReconcileStateConflict,
			},
		},
		Pending: 1,
	}

	got := pendingGenerationIDs(plan)

	if len(got) != 1 {
		t.Fatalf(
			"generation count = %d, want 1",
			len(got),
		)
	}

	if got[0] != "generation-b" {
		t.Fatalf(
			"GenerationID = %q, want generation-b",
			got[0],
		)
	}
}

func TestSelectPendingAllowsExpiredJournalRejection(t *testing.T) {
	now := time.Date(
		2026,
		time.September,
		20,
		16,
		0,
		0,
		0,
		time.UTC,
	)

	plan := recordingest.ReconcilePlan{
		Items: []recordingest.ReconcilePlanItem{
			{
				Candidate: recordingest.RecordedReceiptCandidate{
					SourceID:     "source-1",
					GenerationID: "generation-a",
				},
				State: recordingest.ReconcileStatePending,
			},
		},
		Pending: 1,
	}

	rejectionTimes := map[string]time.Time{
		"generation-a": now.Add(-16 * time.Minute),
	}

	got, deferredCount, err :=
		selectPending(
			plan,
			now,
			rejectionTimes,
			15*time.Minute,
		)
	if err != nil {
		t.Fatalf(
			"selectPending() error = %v",
			err,
		)
	}

	if deferredCount != 0 {
		t.Fatalf(
			"deferredCount = %d, want 0",
			deferredCount,
		)
	}

	if len(got) != 1 {
		t.Fatalf(
			"pending count = %d, want 1",
			len(got),
		)
	}
}

func TestSelectPendingStopsOnConflict(t *testing.T) {
	plan := recordingest.ReconcilePlan{
		Items: []recordingest.ReconcilePlanItem{
			{
				Candidate: recordingest.RecordedReceiptCandidate{
					SourceID:     "source-1",
					GenerationID: "generation-a",
				},
				State: recordingest.ReconcileStatePending,
			},
			{
				Candidate: recordingest.RecordedReceiptCandidate{
					SourceID:     "source-1",
					GenerationID: "generation-b",
				},
				State:  recordingest.ReconcileStateConflict,
				Detail: "identity differs",
			},
		},
		Pending:  1,
		Conflict: 1,
	}

	if _, _, err :=
		selectPending(
			plan,
			time.Now(),
			nil,
			15*time.Minute,
		); err == nil {
		t.Fatal(
			"selectPending() accepted reconcile conflict",
		)
	}
}
