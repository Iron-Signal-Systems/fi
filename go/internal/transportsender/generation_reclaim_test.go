// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

func TestReclaimGenerationRetirementTombstonesIgnoresActiveGeneration(t *testing.T) {
	generation := createQueuedTransportGenerationFixture(
		t,
		"20260918T161000.000000000Z-1010101010101010",
	)
	stageRoot := filepath.Dir(generation.GenerationDir)

	result, err := ReclaimGenerationRetirementTombstones(
		stageRoot,
		generation.Published.Signed.Descriptor.SourceID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Reclaimed != 0 || result.Resumed != 0 || result.ReclaimedDiskBytes != 0 {
		t.Fatalf("unexpected reclamation result: %+v", result)
	}
	if _, err := os.Lstat(generation.GenerationDir); err != nil {
		t.Fatalf("active generation changed during reclamation scan: %v", err)
	}
}

func TestReclaimGenerationRetirementTombstonesReclaimsVerifiedObject(t *testing.T) {
	stageRoot, retiredPath, transfer := createRetiredGenerationFixture(
		t,
		"20260918T160000.000000000Z-0011223344556677",
	)

	result, err := ReclaimGenerationRetirementTombstones(
		stageRoot,
		transfer.Descriptor.SourceID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Reclaimed != 1 {
		t.Fatalf("reclaimed = %d, want 1", result.Reclaimed)
	}
	if result.Resumed != 0 {
		t.Fatalf("resumed = %d, want 0", result.Resumed)
	}
	wantBytes := transfer.MetadataBytes + transfer.PayloadBytes
	if result.ReclaimedDiskBytes != wantBytes {
		t.Fatalf(
			"reclaimed disk bytes = %d, want %d",
			result.ReclaimedDiskBytes,
			wantBytes,
		)
	}
	if _, err := os.Lstat(retiredPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("retirement tombstone still exists after reclamation: %v", err)
	}

	entries, err := os.ReadDir(stageRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), generationReclaimingDirectoryPrefix) {
			t.Fatalf("reclaiming namespace remains after successful cleanup: %s", entry.Name())
		}
	}
}

func TestReclaimGenerationRetirementTombstonesRejectsMismatchedIdentity(t *testing.T) {
	stageRoot, retiredPath, transfer := createRetiredGenerationFixture(
		t,
		"20260918T162000.000000000Z-2020202020202020",
	)

	wrongPath := filepath.Join(
		stageRoot,
		generationRetiredDirectoryPrefix+strings.Repeat("0", 64),
	)
	if err := publishGenerationDirectory(retiredPath, wrongPath); err != nil {
		t.Fatal(err)
	}

	if _, err := ReclaimGenerationRetirementTombstones(
		stageRoot,
		transfer.Descriptor.SourceID,
	); err == nil {
		t.Fatal("mismatched retirement tombstone identity was reclaimed")
	}
	if _, err := os.Lstat(wrongPath); err != nil {
		t.Fatalf("mismatched retirement tombstone was removed: %v", err)
	}
}

func TestReclaimGenerationRetirementTombstonesRejectsPayloadMutation(t *testing.T) {
	stageRoot, retiredPath, transfer := createRetiredGenerationFixture(
		t,
		"20260918T163000.000000000Z-3030303030303030",
	)

	payloadPath := filepath.Join(
		retiredPath,
		transportgeneration.SealedGenerationPayloadName,
	)
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) == 0 {
		t.Fatal("retired payload is empty")
	}
	payload[len(payload)-1] ^= 0xff
	if err := os.WriteFile(payloadPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := ReclaimGenerationRetirementTombstones(
		stageRoot,
		transfer.Descriptor.SourceID,
	); err == nil {
		t.Fatal("mutated retirement payload was reclaimed")
	}
	if _, err := os.Lstat(retiredPath); err != nil {
		t.Fatalf("mutated retirement tombstone was removed: %v", err)
	}
}

func TestReclaimGenerationRetirementTombstonesRejectsWrongSource(t *testing.T) {
	stageRoot, retiredPath, _ := createRetiredGenerationFixture(
		t,
		"20260918T164000.000000000Z-4040404040404040",
	)

	if _, err := ReclaimGenerationRetirementTombstones(
		stageRoot,
		"other-source.example",
	); err == nil {
		t.Fatal("retirement tombstone for another source was reclaimed")
	}
	if _, err := os.Lstat(retiredPath); err != nil {
		t.Fatalf("wrong-source retirement tombstone was removed: %v", err)
	}
}

func TestReclaimGenerationRetirementTombstonesResumesInterruptedCleanup(t *testing.T) {
	stageRoot, retiredPath, _ := createRetiredGenerationFixture(
		t,
		"20260918T165000.000000000Z-5050505050505050",
	)

	suffix := strings.TrimPrefix(
		filepath.Base(retiredPath),
		generationRetiredDirectoryPrefix,
	)
	reclaimingPath := filepath.Join(
		stageRoot,
		generationReclaimingDirectoryPrefix+suffix,
	)
	if err := publishGenerationDirectory(retiredPath, reclaimingPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(
		reclaimingPath,
		transportgeneration.SignedGenerationMetadataName,
	)); err != nil {
		t.Fatal(err)
	}

	result, err := ReclaimGenerationRetirementTombstones(
		stageRoot,
		"iss-fs-01.iss.local",
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.Resumed != 1 {
		t.Fatalf("resumed = %d, want 1", result.Resumed)
	}
	if result.Reclaimed != 0 {
		t.Fatalf("reclaimed = %d, want 0", result.Reclaimed)
	}
	if _, err := os.Lstat(reclaimingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("interrupted reclaiming object still exists: %v", err)
	}
}

func createRetiredGenerationFixture(
	t *testing.T,
	generationID string,
) (
	stageRoot string,
	retiredPath string,
	transfer transportgeneration.TransferResult,
) {
	t.Helper()

	generation := createQueuedTransportGenerationFixture(t, generationID)
	transfer = exactTransportGenerationResult(t, generation)
	acknowledgement, err := transportgeneration.NewAcknowledgement(
		transportgeneration.AcknowledgementOutcomeRecorded,
		transfer,
	)
	if err != nil {
		t.Fatal(err)
	}

	var encoded bytes.Buffer
	if err := transportgeneration.WriteAcknowledgement(
		&encoded,
		acknowledgement,
	); err != nil {
		t.Fatal(err)
	}
	authorization, err := VerifyGenerationAcknowledgement(
		&encoded,
		transfer,
	)
	if err != nil {
		t.Fatal(err)
	}

	retirement, err := RetireTransportGeneration(
		generation,
		authorization,
	)
	if err != nil {
		t.Fatal(err)
	}
	if retirement.Disposition != GenerationRetirementDispositionRetired {
		t.Fatalf("retirement disposition = %q", retirement.Disposition)
	}

	return filepath.Dir(generation.GenerationDir), retirement.RetiredPath, transfer
}
