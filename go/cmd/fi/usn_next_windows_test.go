// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"errors"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/checkpoint"
)

func TestValidateUSNNextBatch(t *testing.T) {
	assessment, batch := testUSNNextState()

	if err := validateUSNNextBatch(assessment, batch); err != nil {
		t.Fatalf("valid batch rejected: %v", err)
	}
}

func TestValidateUSNNextBatchRejectsJournalChange(t *testing.T) {
	assessment, batch := testUSNNextState()
	batch.JournalID = "778"

	if err := validateUSNNextBatch(assessment, batch); err == nil {
		t.Fatal("journal change accepted")
	}
}

func TestValidateUSNNextBatchRejectsWrongStart(t *testing.T) {
	assessment, batch := testUSNNextState()
	batch.StartUSN = "151"

	if err := validateUSNNextBatch(assessment, batch); err == nil {
		t.Fatal("wrong start USN accepted")
	}
}

func TestValidateUSNNextBatchRejectsGap(t *testing.T) {
	assessment, batch := testUSNNextState()
	assessment.Status = checkpoint.ContinuityGap
	assessment.ReasonCode = "CheckpointAgedOut"

	if err := validateUSNNextBatch(assessment, batch); !errors.Is(err, ErrUSNContinuityGap) {
		t.Fatalf("error = %v, want ErrUSNContinuityGap", err)
	}
}

func testUSNNextState() (checkpoint.ContinuityAssessment, records.USNReadBatch) {
	volume := records.VolumeIdentity{
		MethodVersion: "windows-file-id-info-ntfs/0.1",
		VolumeGUID:    `\\?\Volume{6d8101b5-0000-0000-0000-501f00000000}\`,
		VolumeSerial:  "5528245215150056436",
	}

	root := records.GovernedRootIdentity{
		ScopeID:        "manual-test",
		VolumeIdentity: volume,
		ObjectIdentity: records.NTFSObjectIdentity{
			MethodVersion:       "windows-file-id-info-ntfs/0.1",
			FileReferenceNumber: "42",
			SequenceNumber:      "8",
		},
	}

	value := checkpoint.USNCheckpoint{
		Version:      checkpoint.SchemaVersion,
		ScopeID:      "manual-test",
		GovernedRoot: root,
		JournalID:    "777",
		NextUSN:      "150",
		UpdatedAt:    "2026-08-23T20:00:00Z",
	}

	assessment := checkpoint.ContinuityAssessment{
		Status:     checkpoint.ContinuityContinuous,
		Checkpoint: value,
	}

	batch := records.USNReadBatch{
		ScopeID:        "manual-test",
		VolumeIdentity: volume,
		JournalID:      "777",
		StartUSN:       "150",
		NextUSN:        "175",
	}

	return assessment, batch
}
