// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"errors"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func TestValidateBaselineSpoolForCheckpointComplete(t *testing.T) {
	summary := spoolRunSummary{
		FileObservations: 2,
		Batches:          []spool.FinalizedBatch{{}, {}},
		VerifiedBatches:  2,
	}
	if err := validateBaselineSpoolForCheckpoint(summary); err != nil {
		t.Fatalf("complete baseline rejected: %v", err)
	}
}

func TestValidateBaselineSpoolForCheckpointRejectsCollectionError(t *testing.T) {
	summary := spoolRunSummary{
		FileObservations: 2,
		CollectionErrors: 1,
		Batches:          []spool.FinalizedBatch{{}},
		VerifiedBatches:  1,
	}
	if err := validateBaselineSpoolForCheckpoint(summary); !errors.Is(err, ErrBaselineCollectionIncomplete) {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateBaselineSpoolForCheckpointRejectsHashError(t *testing.T) {
	summary := spoolRunSummary{
		FileObservations: 2,
		HashErrors:       1,
		Batches:          []spool.FinalizedBatch{{}},
		VerifiedBatches:  1,
	}
	if err := validateBaselineSpoolForCheckpoint(summary); !errors.Is(err, ErrBaselineCollectionIncomplete) {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateBaselineSpoolForCheckpointRejectsUnverifiedBatch(t *testing.T) {
	summary := spoolRunSummary{
		FileObservations: 2,
		Batches:          []spool.FinalizedBatch{{}, {}},
		VerifiedBatches:  1,
	}
	if err := validateBaselineSpoolForCheckpoint(summary); !errors.Is(err, ErrBaselineCollectionIncomplete) {
		t.Fatalf("error = %v", err)
	}
}
