// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"errors"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

func TestSourceConflictQuarantineKeepsHealthySourceScheduled(
	t *testing.T,
) {
	states, err := newSourceSessionStates(workerConfig{
		RepairInterval: time.Hour,
		SourceIDs: []string{
			"iss-fs-19.iss.local",
			"iss-fs-22.iss.local",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	states[0].Repair.Observe(true)

	conflict := reconcileConflictError(recordingest.ReconcilePlan{
		Conflict: 1,
		Items: []recordingest.ReconcilePlanItem{
			{
				Candidate: recordingest.RecordedReceiptCandidate{
					SourceID:     "iss-fs-19.iss.local",
					GenerationID: "generation-conflict",
				},
				Detail: "authoritative receipt mismatch",
				State:  recordingest.ReconcileStateConflict,
			},
		},
	})
	if conflict == nil {
		t.Fatal("expected reconciliation conflict")
	}

	calls := make(map[string]int)
	runner := func(state *sourceSessionState) error {
		sourceID := state.Config.SourceID
		calls[sourceID]++
		if sourceID == "iss-fs-19.iss.local" {
			return conflict
		}
		return nil
	}

	for pass := 0; pass < 2; pass++ {
		for index := range states {
			if err := runScheduledSourcePass(
				&states[index],
				runner,
			); err != nil {
				t.Fatal(err)
			}
		}
	}

	if !states[0].Quarantined {
		t.Fatal("conflicting source was not quarantined")
	}
	if states[1].Quarantined {
		t.Fatal("healthy source was quarantined")
	}
	if calls["iss-fs-19.iss.local"] != 1 {
		t.Fatalf("conflicting source calls = %d, want 1",
			calls["iss-fs-19.iss.local"])
	}
	if calls["iss-fs-22.iss.local"] != 2 {
		t.Fatalf("healthy source calls = %d, want 2",
			calls["iss-fs-22.iss.local"])
	}
	if states[0].Repair.CleanCount() != 0 {
		t.Fatal("quarantined source repair cadence was not reset")
	}
}

func TestSourceConflictQuarantinePreservesGlobalErrors(
	t *testing.T,
) {
	state := &sourceSessionState{
		Config: workerConfig{
			SourceID: "iss-fs-19.iss.local",
		},
	}
	databaseFailure := errors.New("PostgreSQL unavailable")

	err := runScheduledSourcePass(
		state,
		func(*sourceSessionState) error {
			return databaseFailure
		},
	)
	if !errors.Is(err, databaseFailure) {
		t.Fatalf("global error lost: %v", err)
	}
	if state.Quarantined {
		t.Fatal("database failure was incorrectly source-quarantined")
	}
}

func TestSourceConflictQuarantineRejectsIdentityMismatch(
	t *testing.T,
) {
	state := &sourceSessionState{
		Config: workerConfig{
			SourceID: "iss-fs-22.iss.local",
		},
	}

	conflict := &sourceReconcileConflictError{
		Detail:       "identity mismatch",
		GenerationID: "generation-conflict",
		SourceID:     "iss-fs-19.iss.local",
	}

	if err := quarantineSourceConflict(
		state, conflict,
	); err == nil {
		t.Fatal("cross-source conflict identity was accepted")
	}
	if state.Quarantined {
		t.Fatal("wrong source was quarantined")
	}
}

func TestSourceConflictErrorPreservesIdentity(
	t *testing.T,
) {
	conflict := reconcileConflictError(recordingest.ReconcilePlan{
		Conflict: 1,
		Items: []recordingest.ReconcilePlanItem{
			{
				Candidate: recordingest.RecordedReceiptCandidate{
					SourceID:     "iss-fs-19.iss.local",
					GenerationID: "generation-conflict",
				},
				Detail: "receipt mismatch",
				State:  recordingest.ReconcileStateConflict,
			},
		},
	})

	var typed *sourceReconcileConflictError
	if !errors.As(conflict, &typed) {
		t.Fatalf("conflict is not typed: %v", conflict)
	}
	if typed.SourceID != "iss-fs-19.iss.local" ||
		typed.GenerationID != "generation-conflict" {
		t.Fatalf("conflict identity changed: %+v", typed)
	}
}
