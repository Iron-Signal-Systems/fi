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

func TestStartupConflictDoesNotPreventHealthySource(
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

	plans := []recordingest.ReconcilePlan{
		{
			Conflict: 1,
			Items: []recordingest.ReconcilePlanItem{
				{
					Candidate: recordingest.RecordedReceiptCandidate{
						SourceID:     "iss-fs-19.iss.local",
						GenerationID: "generation-conflict",
					},
					State:  recordingest.ReconcileStateConflict,
					Detail: "receipt identity mismatch",
				},
			},
		},
		{},
	}

	calls := make(map[string]int)

	for index := range states {
		state := &states[index]

		err := runStartupSourcePlan(
			state,
			plans[index],
			func() error {
				calls[state.Config.SourceID]++
				return nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}
	}

	if !states[0].Quarantined {
		t.Fatal("FS19 was not quarantined")
	}
	if states[1].Quarantined {
		t.Fatal("healthy FS22 was quarantined")
	}
	if calls["iss-fs-19.iss.local"] != 0 {
		t.Fatal("conflicting FS19 performed ingest")
	}
	if calls["iss-fs-22.iss.local"] != 1 {
		t.Fatal("healthy FS22 did not perform startup ingest")
	}
}

func TestStartupNonConflictFailureRemainsFatal(
	t *testing.T,
) {
	state := &sourceSessionState{
		Config: workerConfig{
			SourceID: "iss-fs-19.iss.local",
		},
	}

	failure := errors.New("database failure")

	err := runStartupSourcePlan(
		state,
		recordingest.ReconcilePlan{},
		func() error {
			return failure
		},
	)

	if !errors.Is(err, failure) {
		t.Fatalf("startup failure was not preserved: %v", err)
	}
	if state.Quarantined {
		t.Fatal("database failure incorrectly quarantined source")
	}
}

func TestStartupQuarantinePreventsRepeatedIngest(
	t *testing.T,
) {
	state := &sourceSessionState{
		Config: workerConfig{
			SourceID: "iss-fs-19.iss.local",
		},
		Quarantined: true,
	}

	invoked := false

	err := runStartupSourcePlan(
		state,
		recordingest.ReconcilePlan{},
		func() error {
			invoked = true
			return nil
		},
	)

	if err != nil {
		t.Fatal(err)
	}
	if invoked {
		t.Fatal("quarantined source was processed")
	}
}
