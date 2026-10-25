// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A manually completed rename represents a crash after the durable
// promotion boundary, but before startup reconciliation returned.
func TestRawUSNPromotionRecoversAfterCompletedRename(t *testing.T) {
	fixture := newRealCommittedCustodyFixture(t)

	active := filepath.Join(
		fixture.StageRoot, filepath.Base(fixture.SealedDir),
	)
	if err := publishGenerationDirectory(
		fixture.SealedDir, active,
	); err != nil {
		t.Fatal(err)
	}

	result, err := recoverCommittedRawUSNPromotions(
		context.Background(),
		fixture.RawRoot,
		fixture.StageRoot,
		fixture.StateDir,
		realCustodySourceID,
		64<<20,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Promoted != 0 || result.AlreadyActive != 1 {
		t.Fatalf("incorrect replay disposition: %+v", result)
	}

	fixture.SealedDir = active
	assertRealCustodyCopiesRetained(t, fixture)
}

// Source custody corruption must be rejected before the private sealed
// generation becomes visible to the sender's transport worker.
func TestRawUSNPromotionRejectsChangedCommittedLedger(t *testing.T) {
	fixture := newRealCommittedCustodyFixture(t)

	captureDir := filepath.Join(
		fixture.StateDir,
		"usn-capture-"+realCustodyScopeID,
	)
	entries, err := os.ReadDir(captureDir)
	if err != nil {
		t.Fatal(err)
	}

	changed := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "source-manifests-") {
			continue
		}
		if err := os.WriteFile(
			filepath.Join(captureDir, entry.Name()),
			[]byte(`{"version":"altered"}`),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		changed = true
		break
	}
	if !changed {
		t.Fatal("committed source ledger not found")
	}

	err = RecoverTransportGenerationBuildsWithCustody(
		context.Background(),
		fixture.RawRoot,
		fixture.StageRoot,
		realCustodySourceID,
		64<<20,
		fixture.StateDir,
	)
	if !errors.Is(err, ErrSourceCustodyHandoffRequired) {
		t.Fatalf("altered committed source was accepted: %v", err)
	}

	active := filepath.Join(
		fixture.StageRoot, filepath.Base(fixture.SealedDir),
	)
	if _, err := os.Lstat(active); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("generation promoted despite changed ledger: %v", err)
	}
	assertRealCustodyCopiesRetained(t, fixture)
}

func TestRawUSNPromotionRejectsConflictingNamespaces(t *testing.T) {
	fixture := newRealCommittedCustodyFixture(t)

	active := filepath.Join(
		fixture.StageRoot, filepath.Base(fixture.SealedDir),
	)
	if err := os.Mkdir(active, 0o700); err != nil {
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
	if !errors.Is(err, ErrGenerationSourceCustodyConflict) {
		t.Fatalf("duplicate namespaces accepted: %v", err)
	}
	assertRealCustodyCopiesRetained(t, fixture)
}

func TestRawUSNPromotionRejectsCancelledRecovery(t *testing.T) {
	fixture := newRealCommittedCustodyFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := recoverCommittedRawUSNPromotions(
		ctx,
		fixture.RawRoot,
		fixture.StageRoot,
		fixture.StateDir,
		realCustodySourceID,
		64<<20,
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled recovery accepted: %v", err)
	}
	assertRealCustodyCopiesRetained(t, fixture)
}
