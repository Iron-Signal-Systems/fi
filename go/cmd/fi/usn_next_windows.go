// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/checkpoint"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usn"
)

var ErrUSNContinuityGap = errors.New("USN continuity gap")

// usnNextOutput is operational glue only. It does not reconcile history and it
// does not advance the checkpoint. The future shipper owns the durable handoff
// boundary and can advance only after the USN facts and fresh NTFS observations
// have been accepted downstream.
type usnNextOutput struct {
	StatePath          string                            `json:"state_path"`
	Assessment         checkpoint.ContinuityAssessment   `json:"assessment"`
	StartUSN           string                            `json:"start_usn"`
	ProposedNextUSN    string                            `json:"proposed_next_usn,omitempty"`
	CheckpointAdvanced bool                              `json:"checkpoint_advanced"`
	Result             *usn.JournaledReobservationResult `json:"result,omitempty"`
}

func runUSNNext(governedRoot string) {
	statePath, err := checkpoint.DefaultPath("manual-test")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}

	output, err := collectUSNNext(
		context.Background(),
		"manual-test",
		governedRoot,
		statePath,
	)
	if err != nil {
		if output.Assessment.Status != "" {
			writeIndentedJSON(output)
		}
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}

	writeIndentedJSON(output)
}

func collectUSNNext(
	ctx context.Context,
	scopeID string,
	governedRoot string,
	statePath string,
) (usnNextOutput, error) {
	assessment, err := checkpoint.Check(ctx, scopeID, governedRoot, statePath)
	if err != nil {
		return usnNextOutput{}, err
	}

	output := usnNextOutput{
		StatePath:          statePath,
		Assessment:         assessment,
		StartUSN:           assessment.Checkpoint.NextUSN,
		CheckpointAdvanced: false,
	}

	if assessment.Status != checkpoint.ContinuityContinuous {
		return output, fmt.Errorf("%w: %s", ErrUSNContinuityGap, assessment.ReasonCode)
	}

	result, err := usn.ReadAndReobserveJournaled(
		ctx,
		scopeID,
		governedRoot,
		assessment.Checkpoint.NextUSN,
	)
	if err != nil {
		return output, err
	}

	if err := validateUSNNextBatch(assessment, result.Result.USNBatch); err != nil {
		return output, err
	}

	output.ProposedNextUSN = result.Result.USNBatch.NextUSN
	output.Result = &result
	return output, nil
}

func validateUSNNextBatch(
	assessment checkpoint.ContinuityAssessment,
	batch records.USNReadBatch,
) error {
	if assessment.Status != checkpoint.ContinuityContinuous {
		return ErrUSNContinuityGap
	}
	if batch.ScopeID != assessment.Checkpoint.ScopeID {
		return errors.New("USN batch scope does not match checkpoint")
	}
	if batch.JournalID != assessment.Checkpoint.JournalID {
		return errors.New("USN journal changed between checkpoint check and read")
	}
	if batch.StartUSN != assessment.Checkpoint.NextUSN {
		return errors.New("USN batch did not start at checkpoint NextUSN")
	}
	if batch.VolumeIdentity.VolumeGUID != assessment.Checkpoint.GovernedRoot.VolumeIdentity.VolumeGUID ||
		batch.VolumeIdentity.VolumeSerial != assessment.Checkpoint.GovernedRoot.VolumeIdentity.VolumeSerial {
		return errors.New("USN batch volume does not match checkpoint governed-root volume")
	}
	return nil
}
