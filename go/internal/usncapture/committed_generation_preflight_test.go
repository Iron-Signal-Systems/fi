// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

// The original USN source batch is deliberately reclaimed before preflight.
// The immutable committed ledger and frozen manifests remain the sources of
// attribution. No second collector queue owner is opened.
func committedGenerationFixture(t *testing.T) (string, transportgeneration.PublishedGeneration, SourceManifestLedger) {
	t.Helper()
	store, seg, corr, raw, sealed := m5dSignedFixture(t)
	// FI compares every published manifest against the resolved physical
	// spool directory. Windows may spell that directory differently after
	// rollover, so the fixture must use the same canonical paths as FI.
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
			manifests = append(manifests, filepath.Join(physicalRaw, entry.Name()))
		}
	}
	if err := store.CommitVerifiedSpool(seg, corr, physicalRaw, manifests); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ReclaimAcknowledged(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(store.dir, seg.Name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original captured batch must be reclaimed: %v", err)
	}
	ledger, found, err := ReadCommittedSourceLedgerSnapshot(store.dir, seg.Batch.StartUSN)
	if err != nil || !found {
		t.Fatalf("committed inventory unavailable after reclamation: found=%v err=%v", found, err)
	}
	return raw, sealed, ledger
}

func TestCommittedGenerationPreflightSurvivesCaptureReclamation(t *testing.T) {
	raw, sealed, ledger := committedGenerationFixture(t)
	proof, err := VerifyCommittedGenerationPreflight(
		context.Background(), raw, sealed.DirectoryPath, "m5d-source", []SourceManifestLedger{ledger},
	)
	if err != nil {
		t.Fatal(err)
	}
	if proof.SourceID != "m5d-source" || proof.GenerationID != "m5a-test" ||
		proof.CanonicalSHA256 != sealed.Signed.Descriptor.CanonicalSHA256 ||
		len(proof.SourceBatchSHA256) != 1 || proof.SourceBatchSHA256[0] != ledger.SourceBatchSHA256 ||
		len(proof.SourceLedgerSHA256) != 1 || proof.SourceLedgerSHA256[0] != ledger.SHA256 {
		t.Fatalf("incorrect committed source-to-sealed identity: %+v", proof)
	}
}

func TestCommittedGenerationPreflightRejectsIncompleteCandidateSet(t *testing.T) {
	raw, sealed, ledger := committedGenerationFixture(t)
	if _, err := VerifyCommittedGenerationPreflight(context.Background(), raw, sealed.DirectoryPath, "m5d-source", nil); err == nil {
		t.Fatal("missing committed source set accepted")
	}
	if _, err := VerifyCommittedGenerationPreflight(context.Background(), raw, sealed.DirectoryPath, "m5d-source", []SourceManifestLedger{ledger, ledger}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate committed source accepted: %v", err)
	}
	ledger.SourceBatchSHA256 = strings.Repeat("b", 64)
	if _, err := VerifyCommittedGenerationPreflight(context.Background(), raw, sealed.DirectoryPath, "m5d-source", []SourceManifestLedger{ledger}); err == nil {
		t.Fatal("mutated source ledger accepted")
	}
}

func TestCommittedGenerationPreflightRejectsWrongSourceAndTamperedPayload(t *testing.T) {
	raw, sealed, ledger := committedGenerationFixture(t)
	if _, err := VerifyCommittedGenerationPreflight(context.Background(), raw, sealed.DirectoryPath, "other-source", []SourceManifestLedger{ledger}); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong sealed source accepted: %v", err)
	}
	if err := os.WriteFile(sealed.PayloadPath, []byte("altered sealed bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCommittedGenerationPreflight(context.Background(), raw, sealed.DirectoryPath, "m5d-source", []SourceManifestLedger{ledger}); err == nil {
		t.Fatal("altered sealed generation accepted")
	}
}

// A frozen FI generation may contain independently manifested Security records.
// They participate in canonical verification but cannot claim any USN digest.
func TestCommittedGenerationPreflightRejectsUnownedUSNRecord(t *testing.T) {
	raw, sealed, ledger := committedGenerationFixture(t)
	writer, err := spool.NewWriter(raw, 1, spool.CollectorIdentity{
		ExecutablePath:   `C:\Program Files\FI\fi-collector.exe`,
		ExecutableSHA256: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Append("USNReadBoundary", ledger.ScopeID, struct {
		SourceBatchSHA256 string `json:"source_batch_sha256"`
	}{strings.Repeat("b", 64)}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyCommittedGenerationPreflight(context.Background(), raw, sealed.DirectoryPath, "m5d-source", []SourceManifestLedger{ledger}); !errors.Is(err, ErrConflict) {
		t.Fatalf("unaccounted source was accepted: %v", err)
	}
}

// The same signed generation may contain both USN source-bound and unrelated
// FI records. A committed ledger is required for the former, not the latter.
func TestCommittedGenerationPreflightAllowsUnrelatedFIBatches(t *testing.T) {
	store, seg, corr, dir, _ := sampleSpoolPublication(t, false, false)
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	writer, err := spool.NewWriter(dir, 1, spool.CollectorIdentity{
		ExecutablePath:   `C:\Program Files\FI\fi-collector.exe`,
		ExecutableSHA256: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Append("WindowsSecurityEvent", seg.Batch.ScopeID, map[string]string{"event_id": "4663"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	raw := freezeTestSpool(t, dir)
	if _, err := store.RecordSourceManifestLedger(seg, corr, dir); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "m5d-source"},
		KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := transportgeneration.CreateSealedGeneration(
		context.Background(), transportgeneration.CreateConfig{
			FrozenDir: raw, GenerationID: "m5a-test", SourceID: "m5d-source",
			SealedRoot:  filepath.Join(t.TempDir(), "seals"),
			BatchSigner: key, BatchSigningCertificate: cert,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	locations, err := store.InspectPendingPublicationCustody(seg, corr, dir)
	if err != nil || len(locations) != 1 {
		t.Fatalf("source ownership not uniquely located: locations=%v err=%v", locations, err)
	}
	if err := store.CommitVerifiedSpool(seg, corr, raw, locations[0].ManifestPaths); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ReclaimAcknowledged(); err != nil {
		t.Fatal(err)
	}
	ledger, found, err := ReadCommittedSourceLedgerSnapshot(store.dir, seg.Batch.StartUSN)
	if err != nil || !found {
		t.Fatalf("source ledger after reclaim: found=%v err=%v", found, err)
	}
	proof, err := VerifyCommittedGenerationPreflight(
		context.Background(), raw, sealed.DirectoryPath, "m5d-source", []SourceManifestLedger{ledger},
	)
	if err != nil || len(proof.SourceBatchSHA256) != 1 {
		t.Fatalf("valid mixed FI generation rejected: proof=%+v err=%v", proof, err)
	}
}
