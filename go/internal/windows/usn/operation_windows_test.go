// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"context"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestInterruptedRecoveryEnabledByDefault(t *testing.T) {
	if !shouldRecoverInterrupted(context.Background()) {
		t.Fatal("standalone USN operation unexpectedly suppressed restart recovery")
	}
}

func TestWithoutInterruptedRecovery(t *testing.T) {
	ctx := WithoutInterruptedRecovery(context.Background())
	if shouldRecoverInterrupted(ctx) {
		t.Fatal("nested USN operation did not suppress restart recovery")
	}
}

func TestReobservationOperationOutcomeCompleteForExpectedStates(t *testing.T) {
	result := ReobservationBatch{
		Reobservations: []ChangeReobservation{
			{Status: ReobservationObserved},
			{Status: ReobservationOutsideGovernedRoot},
			{Status: ReobservationUnavailable},
		},
	}
	outcome, reason := reobservationOperationOutcome(context.Background(), result)
	if outcome != records.OperationComplete || reason != "" {
		t.Fatalf("got %q %q", outcome, reason)
	}
}

func TestReobservationOperationOutcomePartialOnCollectionError(t *testing.T) {
	result := ReobservationBatch{
		Reobservations: []ChangeReobservation{{Status: ReobservationError}},
	}
	outcome, reason := reobservationOperationOutcome(context.Background(), result)
	if outcome != records.OperationPartial || reason != "OneOrMoreReobservationsFailed" {
		t.Fatalf("got %q %q", outcome, reason)
	}
}

func TestReobservationOperationOutcomeInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outcome, reason := reobservationOperationOutcome(ctx, ReobservationBatch{})
	if outcome != records.OperationInterrupted || reason != "ContextCanceled" {
		t.Fatalf("got %q %q", outcome, reason)
	}
}
