// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package main

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationready"
	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
	"github.com/jackc/pgx/v5"
)

const (
	repairIntermediateInterval  = 12 * time.Hour
	repairSteadyInterval        = 24 * time.Hour
	repairValidationCleanTarget = uint64(6)
)

type repairMode string

const (
	repairModeIntermediate repairMode = "Intermediate"
	repairModeSteady       repairMode = "Steady"
	repairModeValidation   repairMode = "Validation"
)

type repairCadence struct {
	cleanCount         uint64
	mode               repairMode
	validationInterval time.Duration
}

func newRepairCadence(
	validationInterval time.Duration,
) repairCadence {
	return repairCadence{
		mode:               repairModeValidation,
		validationInterval: validationInterval,
	}
}

func (cadence *repairCadence) CleanCount() uint64 {
	if cadence == nil {
		return 0
	}
	return cadence.cleanCount
}

func (cadence *repairCadence) Interval() time.Duration {
	if cadence == nil {
		return 0
	}

	switch cadence.mode {
	case repairModeIntermediate:
		return repairIntermediateInterval
	case repairModeSteady:
		return repairSteadyInterval
	default:
		return cadence.validationInterval
	}
}

func (cadence *repairCadence) Mode() repairMode {
	if cadence == nil {
		return repairModeValidation
	}
	return cadence.mode
}

func (cadence *repairCadence) Observe(clean bool) {
	if cadence == nil {
		return
	}

	if !clean {
		cadence.Reset()
		return
	}

	cadence.cleanCount++

	switch cadence.mode {
	case repairModeValidation:
		if cadence.cleanCount >= repairValidationCleanTarget {
			cadence.mode = repairModeIntermediate
		}
	case repairModeIntermediate:
		cadence.mode = repairModeSteady
	}
}

func (cadence *repairCadence) Reset() {
	if cadence == nil {
		return
	}

	cadence.cleanCount = 0
	cadence.mode = repairModeValidation
}

type repairAssessment struct {
	Conflict          uint64
	KnownRejected     uint64
	ReadyNotified     uint64
	UnexpectedPending uint64
}

func (assessment repairAssessment) Clean() bool {
	return assessment.Conflict == 0 &&
		assessment.UnexpectedPending == 0
}

func assessRepairPlan(
	ctx context.Context,
	config workerConfig,
	connection *pgx.Conn,
	plan recordingest.ReconcilePlan,
) (
	repairAssessment,
	error,
) {
	if ctx == nil || connection == nil {
		return repairAssessment{},
			errors.New(
				"FI repair assessment PostgreSQL connection is required",
			)
	}

	rejectionTimes, err :=
		recordingest.LoadSourceRecordRejectionTimes(
			ctx,
			connection,
			config.SourceID,
			pendingGenerationIDs(plan),
		)
	if err != nil {
		return repairAssessment{}, err
	}

	return assessRepairPlanState(
		plan,
		rejectionTimes,
		func(receiptName string) (bool, error) {
			return generationready.ReceiptNamePresent(
				config.ReadyRoot,
				receiptName,
			)
		},
	)
}

func assessRepairPlanState(
	plan recordingest.ReconcilePlan,
	rejectionTimes map[string]time.Time,
	markerPresent func(string) (bool, error),
) (
	repairAssessment,
	error,
) {
	assessment := repairAssessment{
		Conflict: plan.Conflict,
	}

	for _, item := range plan.Items {
		if item.State != recordingest.ReconcileStatePending {
			continue
		}

		if _, found :=
			rejectionTimes[item.Candidate.GenerationID]; found {
			assessment.KnownRejected++
			continue
		}

		if markerPresent == nil {
			return repairAssessment{},
				errors.New(
					"FI repair assessment READY marker lookup is required",
				)
		}

		present, err :=
			markerPresent(
				filepath.Base(item.Candidate.Path),
			)
		if err != nil {
			return repairAssessment{}, err
		}

		if present {
			assessment.ReadyNotified++
			continue
		}

		assessment.UnexpectedPending++
	}

	return assessment, nil
}
