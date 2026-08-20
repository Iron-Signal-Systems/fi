// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package ntfs

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestObservationConsistencyCompleteRejectsStreamError(t *testing.T) {
	observation := Observation{
		ObservationStatus: records.ObservationComplete,
		StreamInventory: records.StreamInventory{
			State:      records.ObservationStateError,
			ReasonCode: "StreamEnumerationFailed",
		},
		Warnings: []records.ObservationWarning{{Code: "StreamEnumerationFailed"}},
	}
	if err := validateObservationConsistency(observation); err == nil {
		t.Fatal("expected conflict")
	}
}

func TestObservationConsistencyPartialRequiresPartialCondition(t *testing.T) {
	observation := Observation{
		ObservationStatus: records.ObservationPartial,
		StreamInventory: records.StreamInventory{
			State: records.ObservationStatePresent,
		},
	}
	if err := validateObservationConsistency(observation); err == nil {
		t.Fatal("expected conflict")
	}
}

func TestObservationConsistencyChangedRequiresMetadataWarning(t *testing.T) {
	observation := Observation{
		ObservationStatus: records.ObservationChangedDuringCollection,
		StreamInventory: records.StreamInventory{
			State: records.ObservationStatePresent,
		},
	}
	if err := validateObservationConsistency(observation); err == nil {
		t.Fatal("expected conflict")
	}
}

func TestObservationConsistencyReplacedRequiresReplacementWarning(t *testing.T) {
	observation := Observation{
		ObservationStatus: records.ObservationReplacedDuringCollection,
		StreamInventory: records.StreamInventory{
			State: records.ObservationStatePresent,
		},
	}
	if err := validateObservationConsistency(observation); err == nil {
		t.Fatal("expected conflict")
	}
}

func TestObservationConsistencyValidComplete(t *testing.T) {
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
	}
	if err := validateObservationConsistency(observation); err != nil {
		t.Fatal(err)
	}
}
