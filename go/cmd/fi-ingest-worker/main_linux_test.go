// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package main

import (
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

func TestSelectPendingSkipsAcceptedAndDeferred(t *testing.T) {
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

	deferred := map[string]time.Time{
		"source-1\x00generation-b": now.Add(10 * time.Minute),
	}

	got, deferredCount, err :=
		selectPending(
			plan,
			now,
			deferred,
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
		); err == nil {
		t.Fatal(
			"selectPending() accepted reconcile conflict",
		)
	}
}
