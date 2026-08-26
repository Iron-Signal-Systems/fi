//go:build windows

package main

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/securityevent"
)

func TestNewWindowsSecurityContinuityGapObservation(t *testing.T) {
	assessment := securityevent.ContinuityAssessment{
		Status:     securityevent.ContinuityGap,
		ReasonCode: "SecurityLogRecordsOverwritten",
		Checkpoint: securityevent.Checkpoint{
			LastEventRecordID: "100",
		},
		LogState: securityevent.LogState{
			ObservedAt:          "2026-08-26T12:00:00.1234567Z",
			Channel:             "Security",
			OldestEventRecordID: "200",
			NewestEventRecordID: "300",
		},
	}

	value, err := newWindowsSecurityContinuityGapObservation(assessment)
	if err != nil {
		t.Fatal(err)
	}
	if value.ObservedAt != "2026-08-26T12:00:00.123456700Z" {
		t.Fatalf("observed_at=%q", value.ObservedAt)
	}
	if value.CheckpointEventRecordID != "100" ||
		value.CurrentOldestEventRecordID != "200" ||
		value.CurrentNewestEventRecordID != "300" ||
		value.ReconciliationAction != records.WindowsSecurityContinuityGapReconcileCurrentStateBaseline {
		t.Fatalf("unexpected gap observation: %+v", value)
	}
	if err := records.ValidateWindowsSecurityContinuityGapObservation(value); err != nil {
		t.Fatal(err)
	}
}
