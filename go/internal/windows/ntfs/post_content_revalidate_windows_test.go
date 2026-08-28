// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestObservationRelevantNativeStateChangedIgnoresLastAccessTime(t *testing.T) {
	state := nativeState{}
	metadata, subjectKind, err := metadataFromState(state)
	if err != nil {
		t.Fatal(err)
	}
	observation := Observation{Metadata: metadata, SubjectKind: subjectKind}

	state.Basic.LastAccessTime = 123456789
	changed, err := observationRelevantNativeStateChanged(observation, state)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Fatal("LastAccessTime-only change must not invalidate content-read consistency")
	}
}

func TestObservationRelevantNativeStateChangedDetectsLastWriteTime(t *testing.T) {
	state := nativeState{}
	metadata, subjectKind, err := metadataFromState(state)
	if err != nil {
		t.Fatal(err)
	}
	observation := Observation{Metadata: metadata, SubjectKind: subjectKind}

	state.Basic.LastWriteTime = 123456789
	changed, err := observationRelevantNativeStateChanged(observation, state)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("LastWriteTime change must be detected")
	}
}

func TestReparseObservationChangedDetectsStateAndTagChanges(t *testing.T) {
	if reparseObservationChanged(reparseObservationNotPresent(), fileAttributeTagInfo{}) {
		t.Fatal("not-present reparse state changed unexpectedly")
	}
	if !reparseObservationChanged(
		reparseObservationNotPresent(),
		fileAttributeTagInfo{FileAttributes: fileAttributeReparse, ReparseTag: reparseTagSymlink},
	) {
		t.Fatal("new reparse state was not detected")
	}

	present := records.ReparseObservation{
		State: records.ReparseStatePresent,
		Tag:   reparseTagString(reparseTagSymlink),
	}
	if reparseObservationChanged(
		present,
		fileAttributeTagInfo{FileAttributes: fileAttributeReparse, ReparseTag: reparseTagSymlink},
	) {
		t.Fatal("matching reparse state changed unexpectedly")
	}
	if !reparseObservationChanged(
		present,
		fileAttributeTagInfo{FileAttributes: fileAttributeReparse, ReparseTag: reparseTagMountPoint},
	) {
		t.Fatal("reparse tag change was not detected")
	}
}
