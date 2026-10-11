// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"testing"
	"time"
)

func TestNewSourceSessionStatesPreservesRegistryOrder(
	t *testing.T,
) {
	config := workerConfig{
		RepairInterval: time.Hour,
		SourceIDs: []string{
			"app-01.iss.local",
			"fs-03.iss.local",
			"iss-fs-22.iss.local",
		},
	}

	states, err := newSourceSessionStates(config)
	if err != nil {
		t.Fatal(err)
	}

	if len(states) != len(config.SourceIDs) {
		t.Fatalf(
			"state count = %d, want %d",
			len(states),
			len(config.SourceIDs),
		)
	}

	for index, sourceID := range config.SourceIDs {
		if states[index].Config.SourceID != sourceID {
			t.Fatalf(
				"state[%d] source = %q, want %q",
				index,
				states[index].Config.SourceID,
				sourceID,
			)
		}

		if len(states[index].Config.SourceIDs) != 0 {
			t.Fatalf(
				"state[%d] retained outer SourceIDs",
				index,
			)
		}
	}
}

func TestNewSourceSessionStatesHaveIndependentRepairCadence(
	t *testing.T,
) {
	states, err := newSourceSessionStates(
		workerConfig{
			RepairInterval: time.Hour,
			SourceIDs: []string{
				"iss-fs-19.iss.local",
				"iss-fs-22.iss.local",
			},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	states[0].Repair.Observe(true)

	if states[0].Repair.CleanCount() != 1 {
		t.Fatalf(
			"first source clean count = %d, want 1",
			states[0].Repair.CleanCount(),
		)
	}

	if states[1].Repair.CleanCount() != 0 {
		t.Fatalf(
			"second source clean count = %d, want 0",
			states[1].Repair.CleanCount(),
		)
	}
}

func TestNewSourceSessionStatesRejectsNoEnabledSources(
	t *testing.T,
) {
	_, err := newSourceSessionStates(
		workerConfig{
			RepairInterval: time.Hour,
		},
	)

	if err == nil {
		t.Fatal(
			"empty enabled-source registry was accepted",
		)
	}
}

func TestNewSourceSessionStatesRejectsEmptySourceID(
	t *testing.T,
) {
	_, err := newSourceSessionStates(
		workerConfig{
			RepairInterval: time.Hour,
			SourceIDs: []string{
				"iss-fs-22.iss.local",
				"",
			},
		},
	)

	if err == nil {
		t.Fatal(
			"empty source ID was accepted",
		)
	}
}
