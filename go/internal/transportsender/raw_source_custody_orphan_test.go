// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRawUSNOrphanGuardAcceptsExistingTombstone(t *testing.T) {
	fixture := newRealCommittedCustodyFixture(t)

	if err := inspectSourceCustodyReceiptNamespaces(
		context.Background(),
		fixture.RawRoot,
		fixture.StageRoot,
		realCustodySourceID,
	); err != nil {
		t.Fatal(err)
	}

	assertRealCustodyCopiesRetained(t, fixture)
}

func TestRawUSNOrphanGuardRejectsMissingTombstone(t *testing.T) {
	fixture := newRealCommittedCustodyFixture(t)

	// Simulate loss of the original raw namespace without destroying
	// the test data. The retained copy remains outside the raw root.
	preserved := filepath.Join(t.TempDir(), "preserved-raw")
	if err := os.Rename(fixture.Tombstone, preserved); err != nil {
		t.Fatal(err)
	}

	err := RecoverTransportGenerationBuildsWithCustody(
		context.Background(),
		fixture.RawRoot,
		fixture.StageRoot,
		realCustodySourceID,
		64<<20,
		fixture.StateDir,
	)
	if !errors.Is(err, ErrSourceCustodyHandoffRequired) {
		t.Fatalf("orphaned USN receipt accepted: %v", err)
	}

	active := filepath.Join(
		fixture.StageRoot,
		filepath.Base(fixture.SealedDir),
	)
	if _, err := os.Lstat(active); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphaned generation promoted: %v", err)
	}
	if _, err := os.Stat(preserved); err != nil {
		t.Fatalf("preserved test source missing: %v", err)
	}
	if _, err := os.Stat(fixture.SealedDir); err != nil {
		t.Fatalf("private sealed replacement missing: %v", err)
	}
}

func TestRawUSNOrphanGuardRejectsActiveOrphan(t *testing.T) {
	fixture := newRealCommittedCustodyFixture(t)

	active := filepath.Join(
		fixture.StageRoot,
		filepath.Base(fixture.SealedDir),
	)
	if err := os.Rename(fixture.SealedDir, active); err != nil {
		t.Fatal(err)
	}

	preserved := filepath.Join(t.TempDir(), "preserved-raw")
	if err := os.Rename(fixture.Tombstone, preserved); err != nil {
		t.Fatal(err)
	}

	err := RecoverTransportGenerationBuildsWithCustody(
		context.Background(),
		fixture.RawRoot,
		fixture.StageRoot,
		realCustodySourceID,
		64<<20,
		fixture.StateDir,
	)
	if !errors.Is(err, ErrSourceCustodyHandoffRequired) {
		t.Fatalf("active generation with orphaned receipt accepted: %v", err)
	}

	if _, err := os.Stat(active); err != nil {
		t.Fatalf("active sealed replacement missing: %v", err)
	}
}

func TestRawUSNOrphanGuardRejectsDuplicateRawNamespace(t *testing.T) {
	fixture := newRealCommittedCustodyFixture(t)

	raw := filepath.Join(
		fixture.RawRoot,
		generationDirectoryPrefix+realCustodyGenerationID,
	)
	if err := os.Mkdir(raw, 0o700); err != nil {
		t.Fatal(err)
	}

	err := inspectSourceCustodyReceiptNamespaces(
		context.Background(),
		fixture.RawRoot,
		fixture.StageRoot,
		realCustodySourceID,
	)
	if !errors.Is(err, ErrGenerationSourceCustodyConflict) {
		t.Fatalf("duplicate raw namespace accepted: %v", err)
	}

	assertRealCustodyCopiesRetained(t, fixture)
}
