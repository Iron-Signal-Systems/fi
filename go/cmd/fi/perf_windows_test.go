// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

func TestAddPerformanceObservation(t *testing.T) {
	report := performanceReport{
		Collection: performanceCollection{
			WarningCodes: map[string]uint64{},
			ErrorStages:  map[string]uint64{},
		},
	}

	observation := ntfs.Observation{
		GovernedRoot: records.GovernedRootIdentity{
			VolumeIdentity: records.VolumeIdentity{
				VolumeGUID:   `\\?\Volume{00000000-0000-0000-0000-000000000000}\`,
				VolumeSerial: "42",
			},
			ObjectIdentity: records.NTFSObjectIdentity{
				FileReferenceNumber: "100",
				SequenceNumber:      "2",
			},
		},
		SubjectKind: records.SubjectFile,
		Reparse: records.ReparseObservation{
			State: records.ReparseStatePresent,
		},
		StreamInventory: records.StreamInventory{
			Streams: []records.StreamObservation{
				{Identity: records.StreamIdentity{Kind: records.StreamDefaultData}},
				{Identity: records.StreamIdentity{Kind: records.StreamNamedData}},
			},
		},
		ObservationStatus: records.ObservationPartial,
		Warnings: []records.ObservationWarning{
			{Code: "StreamEnumerationFailed"},
		},
	}

	addPerformanceObservation(&report, observation)

	if report.Collection.Observations != 1 || report.Collection.Files != 1 {
		t.Fatalf("unexpected object counts: %+v", report.Collection)
	}
	if report.Collection.NamedDataStreams != 1 || report.Collection.DefaultDataStreams != 1 {
		t.Fatalf("unexpected stream counts: %+v", report.Collection)
	}
	if report.Collection.ReparseObjects != 1 || report.Collection.Partial != 1 {
		t.Fatalf("unexpected state counts: %+v", report.Collection)
	}
	if report.Collection.WarningCodes["StreamEnumerationFailed"] != 1 {
		t.Fatalf("unexpected warning counts: %+v", report.Collection.WarningCodes)
	}
	if report.Root.VolumeSerial != "42" || report.Root.FileReferenceNumber != "100" {
		t.Fatalf("root identity was not recorded: %+v", report.Root)
	}
}

func TestUnsignedDelta(t *testing.T) {
	if got := unsignedDelta(15, 10); got != 5 {
		t.Fatalf("delta = %d, want 5", got)
	}
	if got := unsignedDelta(5, 10); got != 0 {
		t.Fatalf("underflow delta = %d, want 0", got)
	}
}
