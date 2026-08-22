// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

func TestDistinctReobservationCandidatesDeduplicatesObject(t *testing.T) {
	identity := records.NTFSObjectIdentity{
		MethodVersion:       ntfs.IdentityMethodVersion,
		FileReferenceNumber: "283510",
		SequenceNumber:      "19",
	}
	changes := []records.USNChangeObservation{
		{FileIdentity: identity, USN: "100"},
		{FileIdentity: identity, USN: "200"},
		{FileIdentity: identity, USN: "200"},
		{
			FileIdentity: records.NTFSObjectIdentity{
				MethodVersion:       ntfs.IdentityMethodVersion,
				FileReferenceNumber: "144588",
				SequenceNumber:      "8",
			},
			USN: "300",
		},
	}

	got := distinctReobservationCandidates(changes)
	if len(got) != 2 {
		t.Fatalf("candidates = %d, want 2", len(got))
	}
	if got[0].identity != identity {
		t.Fatalf("first identity = %+v", got[0].identity)
	}
	if len(got[0].triggerUSNs) != 2 || got[0].triggerUSNs[0] != "100" || got[0].triggerUSNs[1] != "200" {
		t.Fatalf("first trigger USNs = %v", got[0].triggerUSNs)
	}
}

func TestReobserveBatchObservesObjectInsideGovernedRoot(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "object.txt")
	if err := os.WriteFile(target, []byte("inside"), 0o600); err != nil {
		t.Fatal(err)
	}

	original, err := ntfs.CollectPath(context.Background(), "scope-test", root, target)
	if err != nil {
		t.Fatal(err)
	}

	batch := records.USNReadBatch{
		ScopeID: "scope-test",
		Records: []records.USNChangeObservation{
			{FileIdentity: original.ObjectIdentity, USN: "100"},
			{FileIdentity: original.ObjectIdentity, USN: "200"},
		},
	}
	result := ReobserveBatch(context.Background(), root, batch)
	if len(result.Reobservations) != 1 {
		t.Fatalf("reobservations = %d", len(result.Reobservations))
	}
	got := result.Reobservations[0]
	if got.Status != ReobservationObserved {
		t.Fatalf("status = %q, error = %q", got.Status, got.Error)
	}
	if got.Observation == nil || got.Observation.ObjectIdentity != original.ObjectIdentity {
		t.Fatalf("observation = %+v", got.Observation)
	}
	if got.Observation.CollectionEntryMethod != ntfs.CollectionEntryNTFSFileID {
		t.Fatalf("entry method = %q", got.Observation.CollectionEntryMethod)
	}
}

func TestReobserveBatchMarksObjectOutsideGovernedRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "governed")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}

	outsideObservation, err := ntfs.CollectPath(context.Background(), "scope-wide", base, outside)
	if err != nil {
		t.Fatal(err)
	}

	batch := records.USNReadBatch{
		ScopeID: "scope-test",
		Records: []records.USNChangeObservation{
			{FileIdentity: outsideObservation.ObjectIdentity, USN: "100"},
		},
	}
	result := ReobserveBatch(context.Background(), root, batch)
	if len(result.Reobservations) != 1 {
		t.Fatalf("reobservations = %d", len(result.Reobservations))
	}
	got := result.Reobservations[0]
	if got.Status != ReobservationOutsideGovernedRoot || got.ReasonCode != "OutsideGovernedRoot" {
		t.Fatalf("result = %+v", got)
	}
	if got.Observation != nil {
		t.Fatalf("outside object unexpectedly produced observation: %+v", got.Observation)
	}
}

func TestReobserveBatchMarksDeletedObjectUnavailable(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "deleted.txt")
	if err := os.WriteFile(target, []byte("delete me"), 0o600); err != nil {
		t.Fatal(err)
	}

	original, err := ntfs.CollectPath(context.Background(), "scope-test", root, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}

	batch := records.USNReadBatch{
		ScopeID: "scope-test",
		Records: []records.USNChangeObservation{
			{FileIdentity: original.ObjectIdentity, USN: "100"},
		},
	}
	result := ReobserveBatch(context.Background(), root, batch)
	if len(result.Reobservations) != 1 {
		t.Fatalf("reobservations = %d", len(result.Reobservations))
	}
	got := result.Reobservations[0]
	if got.Status != ReobservationUnavailable {
		t.Fatalf("status = %q, reason = %q, error = %q", got.Status, got.ReasonCode, got.Error)
	}
	if got.ReasonCode != "ObjectUnavailableAfterUSN" {
		t.Fatalf("reason = %q", got.ReasonCode)
	}
}
