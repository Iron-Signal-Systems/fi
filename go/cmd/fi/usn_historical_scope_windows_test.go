// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usn"
)

func TestSelectUSNObjectsForSpoolPropagatesUnavailableRecordedParentChain(t *testing.T) {
	root := testIdentity("1000", "1")
	topDirectory := testIdentity("1001", "2")
	nestedDirectory := testIdentity("1002", "3")
	file := testIdentity("1003", "4")

	reobservations := []usn.ChangeReobservation{
		{FileIdentity: file, Status: usn.ReobservationUnavailable},
		{FileIdentity: nestedDirectory, Status: usn.ReobservationUnavailable},
		{FileIdentity: topDirectory, Status: usn.ReobservationUnavailable},
	}
	changes := map[records.NTFSObjectIdentity][]records.USNChangeObservation{
		file: {
			{FileIdentity: file, ParentIdentity: nestedDirectory, USN: "103"},
		},
		nestedDirectory: {
			{FileIdentity: nestedDirectory, ParentIdentity: topDirectory, USN: "102"},
		},
		topDirectory: {
			{FileIdentity: topDirectory, ParentIdentity: root, USN: "101"},
		},
	}

	selection := selectUSNObjectsForSpool(
		reobservations,
		changes,
		root,
		func(identity records.NTFSObjectIdentity) parentScopeResult {
			switch identity {
			case nestedDirectory, topDirectory:
				return parentScopeResult{Status: parentScopeUnavailable}
			default:
				t.Fatalf("unexpected current parent check: %#v", identity)
				return parentScopeResult{}
			}
		},
	)

	if len(selection.Selected) != 3 {
		t.Fatalf("selected objects = %d, want 3", len(selection.Selected))
	}
	if selection.IgnoredVolumeObjects != 0 || selection.IgnoredVolumeUSNRecords != 0 {
		t.Fatalf("unexpected ignored volume counts: %#v", selection)
	}
	if selection.SelectedUSNRecords != 3 {
		t.Fatalf("selected USN records = %d, want 3", selection.SelectedUSNRecords)
	}

	if selection.Selected[0].Reobservation.FileIdentity != file ||
		selection.Selected[0].ScopeBasis != scopeBasisRecordedAncestorContained {
		t.Fatalf("file selection = %#v", selection.Selected[0])
	}
	if selection.Selected[1].Reobservation.FileIdentity != nestedDirectory ||
		selection.Selected[1].ScopeBasis != scopeBasisRecordedAncestorContained {
		t.Fatalf("nested-directory selection = %#v", selection.Selected[1])
	}
	if selection.Selected[2].Reobservation.FileIdentity != topDirectory ||
		selection.Selected[2].ScopeBasis != scopeBasisRecordedParentContained {
		t.Fatalf("top-directory selection = %#v", selection.Selected[2])
	}
}

func TestSelectUSNObjectsForSpoolDoesNotPropagateFromUnresolvedParent(t *testing.T) {
	root := testIdentity("1100", "1")
	parent := testIdentity("1101", "2")
	ancestor := testIdentity("1102", "3")
	file := testIdentity("1103", "4")

	reobservations := []usn.ChangeReobservation{
		{FileIdentity: file, Status: usn.ReobservationUnavailable},
		{FileIdentity: parent, Status: usn.ReobservationUnavailable},
	}
	changes := map[records.NTFSObjectIdentity][]records.USNChangeObservation{
		file: {
			{FileIdentity: file, ParentIdentity: parent, USN: "202"},
		},
		parent: {
			{FileIdentity: parent, ParentIdentity: ancestor, USN: "201"},
		},
	}

	selection := selectUSNObjectsForSpool(
		reobservations,
		changes,
		root,
		func(identity records.NTFSObjectIdentity) parentScopeResult {
			switch identity {
			case parent:
				return parentScopeResult{Status: parentScopeUnavailable}
			case ancestor:
				return parentScopeResult{Status: parentScopeError, Error: "scope probe failed"}
			default:
				t.Fatalf("unexpected current parent check: %#v", identity)
				return parentScopeResult{}
			}
		},
	)

	if len(selection.Selected) != 1 {
		t.Fatalf("selected objects = %d, want 1", len(selection.Selected))
	}
	if selection.Selected[0].Reobservation.FileIdentity != parent ||
		selection.Selected[0].ScopeBasis != scopeBasisUnresolvedIncluded {
		t.Fatalf("parent selection = %#v", selection.Selected[0])
	}
	if selection.ScopeUnresolvedObjects != 1 {
		t.Fatalf("scope unresolved objects = %d, want 1", selection.ScopeUnresolvedObjects)
	}
	if selection.IgnoredVolumeObjects != 1 || selection.IgnoredVolumeUSNRecords != 1 {
		t.Fatalf("ignored volume counts = (%d,%d), want (1,1)", selection.IgnoredVolumeObjects, selection.IgnoredVolumeUSNRecords)
	}
}

func TestSelectUSNObjectsForSpoolDoesNotPropagateUnavailableCycle(t *testing.T) {
	root := testIdentity("1200", "1")
	first := testIdentity("1201", "2")
	second := testIdentity("1202", "3")

	reobservations := []usn.ChangeReobservation{
		{FileIdentity: first, Status: usn.ReobservationUnavailable},
		{FileIdentity: second, Status: usn.ReobservationUnavailable},
	}
	changes := map[records.NTFSObjectIdentity][]records.USNChangeObservation{
		first: {
			{FileIdentity: first, ParentIdentity: second, USN: "301"},
		},
		second: {
			{FileIdentity: second, ParentIdentity: first, USN: "302"},
		},
	}

	selection := selectUSNObjectsForSpool(
		reobservations,
		changes,
		root,
		func(records.NTFSObjectIdentity) parentScopeResult {
			return parentScopeResult{Status: parentScopeUnavailable}
		},
	)

	if len(selection.Selected) != 0 {
		t.Fatalf("unanchored cycle selected objects: %#v", selection.Selected)
	}
	if selection.IgnoredVolumeObjects != 2 || selection.IgnoredVolumeUSNRecords != 2 {
		t.Fatalf("ignored volume counts = (%d,%d), want (2,2)", selection.IgnoredVolumeObjects, selection.IgnoredVolumeUSNRecords)
	}
}

func TestSelectUSNObjectsForSpoolDoesNotUseOutsideParentAsHistoricalAnchor(t *testing.T) {
	root := testIdentity("1300", "1")
	parent := testIdentity("1301", "2")
	file := testIdentity("1302", "3")

	reobservations := []usn.ChangeReobservation{
		{FileIdentity: file, Status: usn.ReobservationUnavailable},
		{FileIdentity: parent, Status: usn.ReobservationOutsideGovernedRoot},
	}
	changes := map[records.NTFSObjectIdentity][]records.USNChangeObservation{
		file: {
			{FileIdentity: file, ParentIdentity: parent, USN: "402"},
		},
		parent: {
			{FileIdentity: parent, ParentIdentity: root, USN: "401"},
		},
	}

	selection := selectUSNObjectsForSpool(
		reobservations,
		changes,
		root,
		func(identity records.NTFSObjectIdentity) parentScopeResult {
			if identity == parent {
				return parentScopeResult{Status: parentScopeOutside}
			}
			t.Fatalf("unexpected current parent check: %#v", identity)
			return parentScopeResult{}
		},
	)

	if len(selection.Selected) != 1 {
		t.Fatalf("selected objects = %d, want 1", len(selection.Selected))
	}
	if selection.Selected[0].Reobservation.FileIdentity != parent ||
		selection.Selected[0].ScopeBasis != scopeBasisRecordedParentContained {
		t.Fatalf("parent selection = %#v", selection.Selected[0])
	}
	if selection.IgnoredVolumeObjects != 1 {
		t.Fatalf("ignored volume objects = %d, want 1", selection.IgnoredVolumeObjects)
	}
}
