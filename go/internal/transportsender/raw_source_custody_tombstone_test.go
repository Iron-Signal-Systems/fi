// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
	"github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
)

// rawUSNTombstoneFixture creates a signed private generation and a synthetic
// custody receipt. This tests the namespace primitive; independent source
// verification has its own tests in usncapture.
func rawUSNTombstoneFixture(
	t *testing.T,
) (RawGeneration, string, GenerationSourceCustodyReceipt) {
	t.Helper()

	const sourceID = "fi-custody-test-source"
	const generationID = "custody-test"

	root := t.TempDir()
	rawRoot := filepath.Join(root, generationRawRootDirectoryName)
	rawDir := filepath.Join(
		rawRoot, generationDirectoryPrefix+generationID,
	)
	buildRoot := filepath.Join(
		root, "stage", generationTransportBuildRootDirectoryName,
	)

	if err := os.MkdirAll(rawDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(buildRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	sourceHash := strings.Repeat("a", 64)
	data := []byte(
		`{"record_kind":"USNReadBoundary","payload":{"source_batch_sha256":"` +
			sourceHash + `"}}` + "\n",
	)

	writeGenerationTestBatch(
		t, rawDir, "tombstone-test", data,
	)

	key, cert := generationTestSigningCertificate(t, sourceID)

	sealed, err := transportgeneration.CreateSealedGeneration(
		context.Background(),
		transportgeneration.CreateConfig{
			FrozenDir:               rawDir,
			GenerationID:            generationID,
			SourceID:                sourceID,
			SealedRoot:              buildRoot,
			BatchSigner:             key,
			BatchSigningCertificate: cert,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	metadata, err := os.ReadFile(sealed.MetadataPath)
	if err != nil {
		t.Fatal(err)
	}

	metadataSHA := sha256.Sum256(metadata)
	descriptor := sealed.Signed.Descriptor

	proof := usncapture.CommittedGenerationPreflight{
		GenerationID:         generationID,
		SourceID:             sourceID,
		SignedMetadataSHA256: hex.EncodeToString(metadataSHA[:]),
		CanonicalSHA256:      descriptor.CanonicalSHA256,
		EncodedSHA256:        descriptor.EncodedDataSHA256,
		SourceBatchSHA256:    []string{sourceHash},
		SourceLedgerSHA256:   []string{strings.Repeat("b", 64)},
	}

	receipt, err := recordVerifiedGenerationCustody(
		sealed.DirectoryPath, proof,
	)
	if err != nil {
		t.Fatal(err)
	}

	return RawGeneration{
		GenerationDir: rawDir,
		GenerationID:  generationID,
	}, sealed.DirectoryPath, receipt
}

func TestRawUSNTombstonePreservesBytesAndSealedReplacement(
	t *testing.T,
) {
	raw, sealedDir, receipt := rawUSNTombstoneFixture(t)

	tombstone, err := tombstoneVerifiedRawUSNSource(
		context.Background(), raw, sealedDir, receipt,
	)
	if err != nil {
		t.Fatal(err)
	}

	if filepath.Base(tombstone) !=
		rawUSNSourceRetiredPrefix+raw.GenerationID {
		t.Fatalf("wrong tombstone identity: %q", tombstone)
	}
	if _, err := os.Lstat(raw.GenerationDir); !errors.Is(
		err, os.ErrNotExist,
	) {
		t.Fatalf(
			"raw namespace remained after durable rename: %v", err,
		)
	}

	if err := guardRawGenerationRetirement(tombstone); !errors.Is(
		err, ErrSourceCustodyHandoffRequired,
	) {
		t.Fatalf("raw source bytes did not survive rename: %v", err)
	}
	if _, err := transportgeneration.LoadSealedGeneration(
		sealedDir,
	); err != nil {
		t.Fatalf("private sealed replacement lost: %v", err)
	}
}

func TestRawUSNTombstoneRejectsMissingOrConflictingReceipt(
	t *testing.T,
) {
	raw, sealedDir, receipt := rawUSNTombstoneFixture(t)
	receipt.SourceID = "wrong-source"

	if _, err := tombstoneVerifiedRawUSNSource(
		context.Background(), raw, sealedDir, receipt,
	); err == nil {
		t.Fatal("conflicting receipt permitted raw transition")
	}
	if _, err := os.Stat(raw.GenerationDir); err != nil {
		t.Fatalf("raw source lost after rejected receipt: %v", err)
	}
}

func TestRawUSNTombstoneRejectsCorruptedSealedReplacement(
	t *testing.T,
) {
	raw, sealedDir, receipt := rawUSNTombstoneFixture(t)

	sealed, err := transportgeneration.LoadSealedGeneration(sealedDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		sealed.PayloadPath, []byte("modified"), 0o600,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := tombstoneVerifiedRawUSNSource(
		context.Background(), raw, sealedDir, receipt,
	); err == nil {
		t.Fatal("altered sealed replacement permitted transition")
	}
	if _, err := os.Stat(raw.GenerationDir); err != nil {
		t.Fatalf("raw source lost after rejected replacement: %v", err)
	}
}

func TestRawUSNTombstoneRejectsOccupiedDestination(t *testing.T) {
	raw, sealedDir, receipt := rawUSNTombstoneFixture(t)

	tombstone := filepath.Join(
		filepath.Dir(raw.GenerationDir),
		rawUSNSourceRetiredPrefix+raw.GenerationID,
	)
	if err := os.Mkdir(tombstone, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := tombstoneVerifiedRawUSNSource(
		context.Background(), raw, sealedDir, receipt,
	); !errors.Is(err, ErrGenerationSourceCustodyConflict) {
		t.Fatalf("occupied destination not rejected: %v", err)
	}
	if _, err := os.Stat(raw.GenerationDir); err != nil {
		t.Fatalf("raw source lost after namespace conflict: %v", err)
	}
}

func TestRawUSNTombstoneRejectsCancelledContext(t *testing.T) {
	raw, sealedDir, receipt := rawUSNTombstoneFixture(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := tombstoneVerifiedRawUSNSource(
		ctx, raw, sealedDir, receipt,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled transition was accepted: %v", err)
	}
	if _, err := os.Stat(raw.GenerationDir); err != nil {
		t.Fatalf("raw source lost on cancellation: %v", err)
	}
}
