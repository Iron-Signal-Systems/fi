// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"reflect"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usn"
)

func testIdentity(record, sequence string) records.NTFSObjectIdentity {
	return records.NTFSObjectIdentity{
		MethodVersion:       ntfs.IdentityMethodVersion,
		FileReferenceNumber: record,
		SequenceNumber:      sequence,
	}
}

func TestGroupUSNChangesPreservesPerObjectOrder(t *testing.T) {
	first := testIdentity("10", "2")
	second := testIdentity("20", "3")

	input := []records.USNChangeObservation{
		{FileIdentity: first, USN: "100"},
		{FileIdentity: second, USN: "101"},
		{FileIdentity: first, USN: "102"},
	}
	grouped := groupUSNChanges(input)

	got := []string{grouped[first][0].USN, grouped[first][1].USN}
	want := []string{"100", "102"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("first object USNs = %v, want %v", got, want)
	}
	if len(grouped[second]) != 1 || grouped[second][0].USN != "101" {
		t.Fatalf("second object changes = %#v", grouped[second])
	}
}

func TestSelectUSNObjectCurrentObjectContained(t *testing.T) {
	object := testIdentity("30", "1")
	root := testIdentity("40", "1")
	called := false

	selection, keep := selectUSNObjectForSpool(
		usn.ChangeReobservation{
			FileIdentity: object,
			Status:       usn.ReobservationObserved,
			Observation:  &ntfs.Observation{},
		},
		[]records.USNChangeObservation{{FileIdentity: object, ParentIdentity: testIdentity("50", "1")}},
		root,
		func(records.NTFSObjectIdentity) parentScopeResult {
			called = true
			return parentScopeResult{Status: parentScopeOutside}
		},
	)

	if !keep {
		t.Fatal("current contained object was not selected")
	}
	if selection.ScopeBasis != scopeBasisCurrentObjectContained {
		t.Fatalf("scope basis = %q", selection.ScopeBasis)
	}
	if called {
		t.Fatal("parent checker was called for an already-contained object")
	}
}

func TestSelectUSNObjectRecordedRootParentContained(t *testing.T) {
	object := testIdentity("60", "1")
	root := testIdentity("70", "2")

	selection, keep := selectUSNObjectForSpool(
		usn.ChangeReobservation{FileIdentity: object, Status: usn.ReobservationOutsideGovernedRoot},
		[]records.USNChangeObservation{{FileIdentity: object, ParentIdentity: root}},
		root,
		func(records.NTFSObjectIdentity) parentScopeResult {
			t.Fatal("parent checker should not be needed when USN parent is the governed root")
			return parentScopeResult{}
		},
	)

	if !keep || selection.ScopeBasis != scopeBasisRecordedParentContained {
		t.Fatalf("selection = %#v, keep=%v", selection, keep)
	}
}

func TestSelectUSNObjectNestedRecordedParentContained(t *testing.T) {
	object := testIdentity("80", "1")
	root := testIdentity("90", "1")
	parent := testIdentity("91", "1")

	selection, keep := selectUSNObjectForSpool(
		usn.ChangeReobservation{FileIdentity: object, Status: usn.ReobservationUnavailable},
		[]records.USNChangeObservation{{FileIdentity: object, ParentIdentity: parent}},
		root,
		func(identity records.NTFSObjectIdentity) parentScopeResult {
			if identity != parent {
				t.Fatalf("checked parent = %#v", identity)
			}
			return parentScopeResult{Status: parentScopeContained}
		},
	)

	if !keep || selection.ScopeBasis != scopeBasisRecordedParentContained {
		t.Fatalf("selection = %#v, keep=%v", selection, keep)
	}
}

func TestSelectUSNObjectUnrelatedVolumeObjectIgnored(t *testing.T) {
	object := testIdentity("100", "1")
	root := testIdentity("110", "1")
	parent := testIdentity("120", "1")

	selection, keep := selectUSNObjectForSpool(
		usn.ChangeReobservation{FileIdentity: object, Status: usn.ReobservationOutsideGovernedRoot},
		[]records.USNChangeObservation{{FileIdentity: object, ParentIdentity: parent}},
		root,
		func(records.NTFSObjectIdentity) parentScopeResult {
			return parentScopeResult{Status: parentScopeOutside}
		},
	)

	if keep {
		t.Fatalf("unrelated volume object was selected: %#v", selection)
	}
}

func TestSelectUSNObjectUnavailableParentDoesNotForceSelection(t *testing.T) {
	object := testIdentity("130", "1")
	root := testIdentity("140", "1")
	parent := testIdentity("150", "1")

	_, keep := selectUSNObjectForSpool(
		usn.ChangeReobservation{FileIdentity: object, Status: usn.ReobservationUnavailable},
		[]records.USNChangeObservation{{FileIdentity: object, ParentIdentity: parent}},
		root,
		func(records.NTFSObjectIdentity) parentScopeResult {
			return parentScopeResult{Status: parentScopeUnavailable}
		},
	)

	if keep {
		t.Fatal("object with no provable governed-root binding should have been ignored")
	}
}

func TestSelectUSNObjectScopeCheckErrorIncluded(t *testing.T) {
	object := testIdentity("160", "1")
	root := testIdentity("170", "1")
	parent := testIdentity("180", "1")

	selection, keep := selectUSNObjectForSpool(
		usn.ChangeReobservation{FileIdentity: object, Status: usn.ReobservationError},
		[]records.USNChangeObservation{{FileIdentity: object, ParentIdentity: parent}},
		root,
		func(records.NTFSObjectIdentity) parentScopeResult {
			return parentScopeResult{Status: parentScopeError, Error: "scope probe failed"}
		},
	)

	if !keep {
		t.Fatal("unresolved object was silently dropped")
	}
	if selection.ScopeBasis != scopeBasisUnresolvedIncluded || selection.ScopeDetail != "scope probe failed" {
		t.Fatalf("selection = %#v", selection)
	}
}
