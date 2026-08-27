// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestContextReaderStopsBeforeReadWhenCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	reader := contextReader{ctx: ctx, reader: bytes.NewBufferString("source-data")}
	buffer := make([]byte, 32)
	n, err := reader.Read(buffer)
	if n != 0 {
		t.Fatalf("read bytes = %d, want 0", n)
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestApplyContentHashOutcomeMakesObservationPartial(t *testing.T) {
	observation := Observation{
		ObservationStatus: records.ObservationComplete,
	}
	hashes := records.ContentHashObservation{
		State:      records.ContentHashError,
		ReasonCode: "ContentOpenFailed",
		Detail:     "access denied",
	}

	applyContentHashOutcome(&observation, hashes)

	if observation.ObservationStatus != records.ObservationPartial {
		t.Fatalf("status = %q, want %q", observation.ObservationStatus, records.ObservationPartial)
	}
	if len(observation.Warnings) != 1 {
		t.Fatalf("warnings = %d, want 1", len(observation.Warnings))
	}
	if observation.Warnings[0].Code != "ContentHashFailed" {
		t.Fatalf("warning = %q, want ContentHashFailed", observation.Warnings[0].Code)
	}
}

func TestObservationConsistencyAcceptsContentHashFailureAsPartial(t *testing.T) {
	hashes := records.ContentHashObservation{
		State:      records.ContentHashError,
		ReasonCode: "ContentReadFailed",
	}
	observation := Observation{
		ObservationStatus: records.ObservationPartial,
		StreamInventory: records.StreamInventory{
			State: records.ObservationStatePresent,
		},
		Reparse: records.ReparseObservation{
			DataFormat: records.ReparseDataFormatNotApplicable,
			DataState:  records.ReparseDataStateNotApplicable,
			State:      records.ReparseStateNotPresent,
		},
		ContentHashes: &hashes,
		Warnings: []records.ObservationWarning{
			{Code: "ContentHashFailed"},
		},
	}

	if err := validateObservationConsistency(observation); err != nil {
		t.Fatal(err)
	}
}

func TestObservationConsistencyRejectsCompleteContentHashFailure(t *testing.T) {
	hashes := records.ContentHashObservation{
		State:      records.ContentHashError,
		ReasonCode: "ContentReadFailed",
	}
	observation := Observation{
		ObservationStatus: records.ObservationComplete,
		StreamInventory: records.StreamInventory{
			State: records.ObservationStatePresent,
		},
		Reparse: records.ReparseObservation{
			DataFormat: records.ReparseDataFormatNotApplicable,
			DataState:  records.ReparseDataStateNotApplicable,
			State:      records.ReparseStateNotPresent,
		},
		ContentHashes: &hashes,
		Warnings: []records.ObservationWarning{
			{Code: "ContentHashFailed"},
		},
	}

	if err := validateObservationConsistency(observation); err == nil {
		t.Fatal("expected Complete/hash-failure conflict")
	}
}
