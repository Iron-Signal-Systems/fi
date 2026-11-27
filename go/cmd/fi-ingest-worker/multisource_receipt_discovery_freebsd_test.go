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

func TestM1ReceiptDiscoveryQuarantineKeepsHealthySource(t *testing.T) {
	const (
		fs19 = "iss-fs-2019.iss.local"
		fs22 = "iss-fs-22.iss.local"
	)

	states, err := newSourceSessionStates(workerConfig{
		RepairInterval: time.Hour,
		SourceIDs:      []string{fs19, fs22},
	})
	if err != nil {
		t.Fatal(err)
	}

	states[0].Repair.Observe(true)

	corrupted := errors.New("synthetic invalid immutable receipt")

	failure := &recordingest.SourceReceiptDiscoveryError{
		SourceID: fs19,
		Cause:    corrupted,
	}

	calls := make(map[string]int)

	runner := func(state *sourceSessionState) error {
		calls[state.Config.SourceID]++

		if state.Config.SourceID == fs19 {
			return failure
		}
		return nil
	}

	for pass := 0; pass < 3; pass++ {
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
		t.Fatal("FS2019 was not quarantined")
	}
	if states[1].Quarantined {
		t.Fatal("FS22 was incorrectly quarantined")
	}

	if calls[fs19] != 1 || calls[fs22] != 3 {
		t.Fatalf("unexpected calls: %v", calls)
	}

	if states[0].Repair.CleanCount() != 0 {
		t.Fatal("FS2019 repair cadence was not reset")
	}

	// Simulate a new PostgreSQL session using the same worker-owned
	// states, rather than constructing fresh source state.
	retained := states

	if !retained[0].Quarantined || retained[1].Quarantined {
		t.Fatal("source quarantine not retained across session state reuse")
	}

	for index := range retained {
		if err := runScheduledSourcePass(
			&retained[index],
			runner,
		); err != nil {
			t.Fatal(err)
		}
	}

	if calls[fs19] != 1 || calls[fs22] != 4 {
		t.Fatalf("unexpected resumed session calls: %v", calls)
	}
}

func TestM1ReceiptDiscoveryQuarantineRejectsWrongSource(t *testing.T) {
	state := &sourceSessionState{
		Config: workerConfig{
			SourceID: "iss-fs-22.iss.local",
		},
	}

	err := quarantineSourceConflict(
		state,
		&recordingest.SourceReceiptDiscoveryError{
			SourceID: "iss-fs-2019.iss.local",
			Cause:    errors.New("synthetic invalid receipt"),
		},
	)

	if err == nil {
		t.Fatal("wrong source identity was accepted")
	}
	if state.Quarantined {
		t.Fatal("wrong source was quarantined")
	}
}

func TestM1ReceiptDiscoveryQuarantinePreservesGlobalFailure(t *testing.T) {
	state := &sourceSessionState{
		Config: workerConfig{
			SourceID: "iss-fs-2019.iss.local",
		},
	}

	databaseFailure := errors.New("PostgreSQL unavailable")

	err := quarantineSourceConflict(state, databaseFailure)

	if !errors.Is(err, databaseFailure) {
		t.Fatalf("global failure changed: %v", err)
	}
	if state.Quarantined {
		t.Fatal("global failure quarantined source")
	}
}
