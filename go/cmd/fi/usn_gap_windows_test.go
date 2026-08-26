//go:build windows

package main

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/checkpoint"
)

func TestNewUSNContinuityGapObservation(t *testing.T) {
	assessment := checkpoint.ContinuityAssessment{
		CheckedAt:  "2026-08-26T12:00:00.1234567Z",
		Status:     checkpoint.ContinuityGap,
		ReasonCode: "JournalIDChanged",
		Checkpoint: checkpoint.USNCheckpoint{
			ScopeID:   "root-a",
			JournalID: "10",
			NextUSN:   "20",
		},
		JournalState: records.USNJournalState{
			JournalID:      "11",
			FirstUSN:       "30",
			LowestValidUSN: "30",
			NextUSN:        "40",
		},
	}

	value, err := newUSNContinuityGapObservation(`C:\Data`, assessment)
	if err != nil {
		t.Fatal(err)
	}
	if value.ObservedAt != "2026-08-26T12:00:00.123456700Z" {
		t.Fatalf("observed_at=%q", value.ObservedAt)
	}
	if err := records.ValidateUSNContinuityGapObservation(value); err != nil {
		t.Fatal(err)
	}
	if value.ReasonCode != "JournalIDChanged" ||
		value.CheckpointNextUSN != "20" ||
		value.CurrentNextUSN != "40" ||
		value.ReconciliationAction != records.USNContinuityGapReconcileBaselineAndCatchUp {
		t.Fatalf("unexpected gap observation: %+v", value)
	}
}
