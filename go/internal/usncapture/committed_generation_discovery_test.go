// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

// This fixture moves the already-committed capture queue to its configured
// per-scope location, then ensures that its original batch was reclaimed.
func discoveredCommittedGenerationFixture(
	t *testing.T,
) (string, string, transportgeneration.PublishedGeneration, SourceManifestLedger) {
	t.Helper()

	store, seg, corr, raw, sealed := m5dSignedFixture(t)

	physicalRaw, err := spool.PhysicalSpoolDir(raw)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(physicalRaw)
	if err != nil {
		t.Fatal(err)
	}

	var manifests []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".manifest.json") {
			manifests = append(
				manifests,
				filepath.Join(physicalRaw, entry.Name()),
			)
		}
	}

	if err := store.CommitVerifiedSpool(
		seg, corr, raw, manifests,
	); err != nil {
		t.Fatal(err)
	}

	if _, _, err := store.ReclaimAcknowledged(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Lstat(
		filepath.Join(store.dir, seg.Name),
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(
			"original capture segment must be reclaimed: %v", err,
		)
	}

	stateDir := t.TempDir()
	target := filepath.Join(
		stateDir, "usn-capture-"+seg.Batch.ScopeID,
	)

	if err := os.Rename(store.dir, target); err != nil {
		t.Fatal(err)
	}

	ledger, found, err := ReadCommittedSourceLedgerSnapshot(
		target, seg.Batch.StartUSN,
	)
	if err != nil || !found {
		t.Fatalf(
			"committed ledger missing: found=%v err=%v",
			found, err,
		)
	}

	return stateDir, raw, sealed, ledger
}

func TestDiscoverCommittedGenerationLedgersAfterReclamation(
	t *testing.T,
) {
	stateDir, raw, sealed, expected :=
		discoveredCommittedGenerationFixture(t)

	ledgers, err := DiscoverCommittedGenerationLedgers(
		context.Background(), stateDir, raw,
	)

	if err != nil ||
		len(ledgers) != 1 ||
		ledgers[0].SHA256 != expected.SHA256 {
		t.Fatalf(
			"discovery count=%d err=%v", len(ledgers), err,
		)
	}

	proof, err := VerifyDiscoveredCommittedGeneration(
		context.Background(),
		stateDir,
		raw,
		sealed.DirectoryPath,
		"m5d-source",
	)

	if err != nil ||
		proof.GenerationID != sealed.Signed.Descriptor.GenerationID {
		t.Fatalf(
			"complete generation verification=%+v err=%v",
			proof, err,
		)
	}
}

func TestDiscoverCommittedGenerationLedgersRejectsMissingQueue(
	t *testing.T,
) {
	stateDir, raw, _, ledger :=
		discoveredCommittedGenerationFixture(t)

	dir := filepath.Join(
		stateDir, "usn-capture-"+ledger.ScopeID,
	)

	if err := os.Rename(dir, dir+".removed"); err != nil {
		t.Fatal(err)
	}

	if _, err := DiscoverCommittedGenerationLedgers(
		context.Background(), stateDir, raw,
	); err == nil {
		t.Fatal("missing collector custody queue accepted")
	}
}

func TestDiscoverCommittedGenerationLedgersRejectsChangedReceipt(
	t *testing.T,
) {
	stateDir, raw, _, ledger :=
		discoveredCommittedGenerationFixture(t)

	dir := filepath.Join(
		stateDir, "usn-capture-"+ledger.ScopeID,
	)

	name := segmentNameMust(ledger.StartUSN)

	if err := os.WriteFile(
		filepath.Join(dir, "receipt-"+name),
		[]byte(`{"version":"tampered"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := DiscoverCommittedGenerationLedgers(
		context.Background(), stateDir, raw,
	); err == nil {
		t.Fatal("tampered committed processing receipt accepted")
	}
}

func TestDiscoverCommittedGenerationLedgersRejectsWrongSource(
	t *testing.T,
) {
	stateDir, raw, sealed, _ :=
		discoveredCommittedGenerationFixture(t)

	if _, err := VerifyDiscoveredCommittedGeneration(
		context.Background(),
		stateDir,
		raw,
		sealed.DirectoryPath,
		"unrelated-source",
	); !errors.Is(err, ErrConflict) {
		t.Fatalf(
			"wrong FI sender identity accepted: %v", err,
		)
	}
}
