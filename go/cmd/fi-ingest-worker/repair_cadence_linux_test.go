// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package main

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

func TestRepairCadenceTransitionsAndResets(
	t *testing.T,
) {
	cadence := newRepairCadence(time.Hour)

	if cadence.Mode() != repairModeValidation ||
		cadence.Interval() != time.Hour ||
		cadence.CleanCount() != 0 {
		t.Fatalf(
			"initial cadence mode=%s interval=%s clean=%d",
			cadence.Mode(),
			cadence.Interval(),
			cadence.CleanCount(),
		)
	}

	for clean := uint64(1); clean < repairValidationCleanTarget; clean++ {
		cadence.Observe(true)

		if cadence.Mode() != repairModeValidation {
			t.Fatalf(
				"validation clean %d mode=%s, want Validation",
				clean,
				cadence.Mode(),
			)
		}
		if cadence.Interval() != time.Hour {
			t.Fatalf(
				"validation clean %d interval=%s, want 1h",
				clean,
				cadence.Interval(),
			)
		}
	}

	cadence.Observe(true)

	if cadence.Mode() != repairModeIntermediate ||
		cadence.Interval() != 12*time.Hour ||
		cadence.CleanCount() != repairValidationCleanTarget {
		t.Fatalf(
			"post-validation cadence mode=%s interval=%s clean=%d",
			cadence.Mode(),
			cadence.Interval(),
			cadence.CleanCount(),
		)
	}

	cadence.Observe(true)

	if cadence.Mode() != repairModeSteady ||
		cadence.Interval() != 24*time.Hour ||
		cadence.CleanCount() != repairValidationCleanTarget+1 {
		t.Fatalf(
			"post-intermediate cadence mode=%s interval=%s clean=%d",
			cadence.Mode(),
			cadence.Interval(),
			cadence.CleanCount(),
		)
	}

	cadence.Observe(true)

	if cadence.Mode() != repairModeSteady ||
		cadence.CleanCount() != repairValidationCleanTarget+2 {
		t.Fatalf(
			"steady cadence mode=%s clean=%d",
			cadence.Mode(),
			cadence.CleanCount(),
		)
	}

	cadence.Observe(false)

	if cadence.Mode() != repairModeValidation ||
		cadence.Interval() != time.Hour ||
		cadence.CleanCount() != 0 {
		t.Fatalf(
			"reset cadence mode=%s interval=%s clean=%d",
			cadence.Mode(),
			cadence.Interval(),
			cadence.CleanCount(),
		)
	}
}

func TestRepairAssessmentSeparatesExpectedAndUnexpectedPending(
	t *testing.T,
) {
	plan := recordingest.ReconcilePlan{
		Conflict:   0,
		Discovered: 4,
		Pending:    3,
		Accepted:   1,
		Items: []recordingest.ReconcilePlanItem{
			{
				Candidate: recordingest.RecordedReceiptCandidate{
					GenerationID: "accepted",
					Path: filepath.Join(
						"/recorded",
						"generation-accepted.record.json",
					),
				},
				State: recordingest.ReconcileStateAccepted,
			},
			{
				Candidate: recordingest.RecordedReceiptCandidate{
					GenerationID: "rejected",
					Path: filepath.Join(
						"/recorded",
						"generation-rejected.record.json",
					),
				},
				State: recordingest.ReconcileStatePending,
			},
			{
				Candidate: recordingest.RecordedReceiptCandidate{
					GenerationID: "ready",
					Path: filepath.Join(
						"/recorded",
						"generation-ready.record.json",
					),
				},
				State: recordingest.ReconcileStatePending,
			},
			{
				Candidate: recordingest.RecordedReceiptCandidate{
					GenerationID: "missed",
					Path: filepath.Join(
						"/recorded",
						"generation-missed.record.json",
					),
				},
				State: recordingest.ReconcileStatePending,
			},
		},
	}

	rejections := map[string]time.Time{
		"rejected": time.Now(),
	}

	assessment, err :=
		assessRepairPlanState(
			plan,
			rejections,
			func(name string) (bool, error) {
				return name ==
						"generation-ready.record.json",
					nil
			},
		)
	if err != nil {
		t.Fatal(err)
	}

	if assessment.KnownRejected != 1 ||
		assessment.ReadyNotified != 1 ||
		assessment.UnexpectedPending != 1 ||
		assessment.Conflict != 0 {
		t.Fatalf(
			"assessment = %#v",
			assessment,
		)
	}

	if assessment.Clean() {
		t.Fatal("unexpected pending generation was classified clean")
	}
}

func TestRepairAssessmentExpectedPendingIsClean(
	t *testing.T,
) {
	plan := recordingest.ReconcilePlan{
		Discovered: 2,
		Pending:    2,
		Items: []recordingest.ReconcilePlanItem{
			{
				Candidate: recordingest.RecordedReceiptCandidate{
					GenerationID: "rejected",
					Path:         "/recorded/generation-rejected.record.json",
				},
				State: recordingest.ReconcileStatePending,
			},
			{
				Candidate: recordingest.RecordedReceiptCandidate{
					GenerationID: "ready",
					Path:         "/recorded/generation-ready.record.json",
				},
				State: recordingest.ReconcileStatePending,
			},
		},
	}

	assessment, err :=
		assessRepairPlanState(
			plan,
			map[string]time.Time{
				"rejected": time.Now(),
			},
			func(name string) (bool, error) {
				return name ==
						"generation-ready.record.json",
					nil
			},
		)
	if err != nil {
		t.Fatal(err)
	}

	if !assessment.Clean() {
		t.Fatalf(
			"expected pending state classified anomalous: %#v",
			assessment,
		)
	}
}

func TestRepairAssessmentConflictIsNotClean(
	t *testing.T,
) {
	assessment, err :=
		assessRepairPlanState(
			recordingest.ReconcilePlan{
				Conflict: 1,
			},
			nil,
			func(string) (bool, error) {
				return false, errors.New(
					"marker lookup should not be called",
				)
			},
		)
	if err != nil {
		t.Fatal(err)
	}

	if assessment.Clean() {
		t.Fatal("repair conflict was classified clean")
	}
}
