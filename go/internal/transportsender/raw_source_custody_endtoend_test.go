// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
	"github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
)

const (
	realCustodyGenerationID = "real-custody-test"
	realCustodyScopeID      = "root-test"
	realCustodySourceID     = "fi-real-custody-test"
)

// realCommittedCustodyFixture builds one complete collector-to-sender chain.
// The collector commits its original spool publication and reclaims the
// processed capture segment before the sender verifies the frozen generation.
type realCommittedCustodyFixture struct {
	RawRoot   string
	StageRoot string
	StateDir  string
	SealedDir string
	Tombstone string
	Receipt   GenerationSourceCustodyReceipt
}

func newRealCommittedCustodyFixture(t *testing.T) realCommittedCustodyFixture {
	t.Helper()

	ctx := context.Background()
	root := t.TempDir()

	stateDir := filepath.Join(root, "state")
	captureDir := filepath.Join(
		stateDir, "usn-capture-"+realCustodyScopeID,
	)
	spoolDir := filepath.Join(root, "source", "spool")
	rawRoot := filepath.Join(root, "source", generationRawRootDirectoryName)
	stageRoot := filepath.Join(root, "stage")
	buildRoot := filepath.Join(
		stageRoot, generationTransportBuildRootDirectoryName,
	)

	for _, path := range []string{
		stateDir, spoolDir, rawRoot, buildRoot,
	} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	volume := records.VolumeIdentity{
		MethodVersion: "ntfs-volume/1",
		VolumeGUID:    `\\?\Volume{11111111-2222-3333-4444-555555555555}\`,
		VolumeSerial:  "9",
	}
	anchor := usncapture.Cursor{
		Version:        usncapture.SchemaVersion,
		ScopeID:        realCustodyScopeID,
		JournalID:      "19",
		VolumeIdentity: volume,
		NextUSN:        "100",
	}

	if err := usncapture.Initialize(captureDir, anchor); err != nil {
		t.Fatal(err)
	}
	store, err := usncapture.Open(
		captureDir, usncapture.DefaultMaxPendingBytes,
	)
	if err != nil {
		t.Fatal(err)
	}

	rootID := records.NTFSObjectIdentity{
		MethodVersion:       "NTFSFileIdInfo",
		FileReferenceNumber: "10",
		SequenceNumber:      "1",
	}
	fileID := records.NTFSObjectIdentity{
		MethodVersion:       "NTFSFileIdInfo",
		FileReferenceNumber: "30",
		SequenceNumber:      "1",
	}
	now := time.Now().UTC().Format(
		"2006-01-02T15:04:05.000000000Z",
	)

	change := records.USNChangeObservation{
		MajorVersion:      "2",
		MinorVersion:      "0",
		FileIdentity:      fileID,
		ParentIdentity:    rootID,
		USN:               "101",
		Timestamp:         now,
		ReasonRaw:         "256",
		ReasonNames:       []string{"FileCreate"},
		SourceInfoRaw:     "0",
		SecurityID:        "0",
		FileAttributesRaw: "32",
		FileNameUTF16LEBase64URL: base64.RawURLEncoding.EncodeToString(
			[]byte{'x', 0},
		),
	}
	batch := records.USNReadBatch{
		ObservedAt:       now,
		CollectionMethod: "WindowsNTFSUSNJournalV0",
		ScopeID:          realCustodyScopeID,
		JournalID:        "19",
		VolumeIdentity:   volume,
		StartUSN:         "100",
		NextUSN:          "200",
		Records:          []records.USNChangeObservation{change},
	}

	if err := store.Append(batch); err != nil {
		t.Fatal(err)
	}
	segment, found, err := store.Next()
	if err != nil || !found {
		t.Fatalf("read committed capture segment: %v", err)
	}
	correlation, err := store.Correlate(segment, rootID)
	if err != nil {
		t.Fatal(err)
	}
	if len(segment.Work) != 1 {
		t.Fatalf("expected one captured object, got %d", len(segment.Work))
	}

	writer, err := spool.NewWriter(
		spoolDir, 3,
		spool.CollectorIdentity{
			ExecutablePath:   `C:\Program Files\FI\fi-collector.exe`,
			ExecutableSHA256: strings.Repeat("a", 64),
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	boundary := usncapture.SpoolBoundary{
		SourceBatchSHA256:         segment.SHA256,
		CorrelationSHA256:         correlation.SHA256,
		RootIdentity:              rootID,
		JournalID:                 batch.JournalID,
		StartUSN:                  batch.StartUSN,
		NextUSN:                   batch.NextUSN,
		SourceRecordCount:         len(batch.Records),
		SourceDistinctObjectCount: len(segment.Work),
	}
	if err := writer.Append(
		"USNReadBoundary", realCustodyScopeID, boundary,
	); err != nil {
		t.Fatal(err)
	}

	observation := struct {
		SourceBatchSHA256 string                         `json:"source_batch_sha256"`
		FileIdentity      records.NTFSObjectIdentity     `json:"file_identity"`
		Changes           []records.USNChangeObservation `json:"changes"`
		ScopeBasis        string                         `json:"scope_basis"`
		Status            string                         `json:"status"`
	}{
		SourceBatchSHA256: segment.SHA256,
		FileIdentity:      fileID,
		Changes:           []records.USNChangeObservation{change},
		ScopeBasis:        "ScopeUnresolvedIncluded",
		Status:            "Unavailable",
	}
	if err := writer.Append(
		"USNObjectObservation", realCustodyScopeID, observation,
	); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	batches := writer.FinalizedBatches()
	if len(batches) == 0 {
		t.Fatal("FI spool writer produced no finalized manifests")
	}

	if err := store.BeginSpoolPublication(
		segment, correlation,
	); err != nil {
		t.Fatal(err)
	}

	rawDir := filepath.Join(
		rawRoot, generationDirectoryPrefix+realCustodyGenerationID,
	)
	if err := os.Rename(spoolDir, rawDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(spoolDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := store.RecordSourceManifestLedger(
		segment, correlation, spoolDir,
	); err != nil {
		t.Fatal(err)
	}

	physicalRaw, err := spool.PhysicalSpoolDir(rawDir)
	if err != nil {
		t.Fatal(err)
	}
	manifests := make([]string, 0, len(batches))
	for _, published := range batches {
		manifests = append(
			manifests,
			filepath.Join(
				physicalRaw, filepath.Base(published.ManifestPath),
			),
		)
	}

	if err := store.CommitVerifiedSpool(
		segment, correlation, rawDir, manifests,
	); err != nil {
		t.Fatal(err)
	}
	if store.ProcessingCursor().NextUSN != "200" {
		t.Fatal("collector processing cursor did not commit")
	}
	count, _, err := store.ReclaimAcknowledged()
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected one reclaimed segment, got %d", count)
	}

	key, certificate := generationTestSigningCertificate(
		t, realCustodySourceID,
	)
	sealed, err := transportgeneration.CreateSealedGeneration(
		ctx,
		transportgeneration.CreateConfig{
			FrozenDir:               rawDir,
			GenerationID:            realCustodyGenerationID,
			SourceID:                realCustodySourceID,
			SealedRoot:              buildRoot,
			BatchSigner:             key,
			BatchSigningCertificate: certificate,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	proof, err := usncapture.VerifyDiscoveredCommittedGeneration(
		ctx, stateDir, rawDir, sealed.DirectoryPath,
		realCustodySourceID,
	)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := recordVerifiedGenerationCustody(
		sealed.DirectoryPath, proof,
	)
	if err != nil {
		t.Fatal(err)
	}

	raw := RawGeneration{
		GenerationDir: rawDir,
		GenerationID:  realCustodyGenerationID,
	}
	tombstone, err := tombstoneVerifiedRawUSNSource(
		ctx, raw, sealed.DirectoryPath, receipt,
	)
	if err != nil {
		t.Fatal(err)
	}

	return realCommittedCustodyFixture{
		RawRoot:   rawRoot,
		StageRoot: stageRoot,
		StateDir:  stateDir,
		SealedDir: sealed.DirectoryPath,
		Tombstone: tombstone,
		Receipt:   receipt,
	}
}

// TestRawUSNEndToEndCommittedRestart verifies a real committed collector
// queue after the source batch has been reclaimed and the raw source renamed.
func TestRawUSNEndToEndCommittedRestart(t *testing.T) {
	fixture := newRealCommittedCustodyFixture(t)

	states, err := InspectRawUSNCustodyRecoveryWithCommittedState(
		context.Background(),
		fixture.RawRoot,
		fixture.StageRoot,
		fixture.StateDir,
		realCustodySourceID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 ||
		states[0].SealedState != "PRIVATE" ||
		states[0].TombstoneDir != fixture.Tombstone {
		t.Fatalf("unexpected committed recovery state: %+v", states)
	}

	// Startup recovery may now promote the verified sealed replacement.
	// The original raw tombstone must remain intact.
	err = RecoverTransportGenerationBuildsWithCustody(
		context.Background(),
		fixture.RawRoot,
		fixture.StageRoot,
		realCustodySourceID,
		64<<20,
		fixture.StateDir,
	)
	if err != nil {
		t.Fatalf("committed startup recovery failed: %v", err)
	}

	privateDir := fixture.SealedDir
	fixture.SealedDir = filepath.Join(
		fixture.StageRoot, filepath.Base(privateDir),
	)

	if _, err := os.Lstat(privateDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("private generation remains after promotion: %v", err)
	}
	assertRealCustodyCopiesRetained(t, fixture)

	// A restart after the promotion rename must be idempotent.
	if err := RecoverTransportGenerationBuildsWithCustody(
		context.Background(),
		fixture.RawRoot,
		fixture.StageRoot,
		realCustodySourceID,
		64<<20,
		fixture.StateDir,
	); err != nil {
		t.Fatalf("committed recovery replay failed: %v", err)
	}
	assertRealCustodyCopiesRetained(t, fixture)
}

func TestRawUSNEndToEndCommittedRestartAfterPromotion(t *testing.T) {
	fixture := newRealCommittedCustodyFixture(t)

	active := filepath.Join(
		fixture.StageRoot, filepath.Base(fixture.SealedDir),
	)
	if err := os.Rename(fixture.SealedDir, active); err != nil {
		t.Fatal(err)
	}
	fixture.SealedDir = active

	states, err := InspectRawUSNCustodyRecoveryWithCommittedState(
		context.Background(),
		fixture.RawRoot,
		fixture.StageRoot,
		fixture.StateDir,
		realCustodySourceID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 ||
		states[0].SealedState != "ACTIVE" {
		t.Fatalf("promoted recovery state differs: %+v", states)
	}
	assertRealCustodyCopiesRetained(t, fixture)
}

func TestRawUSNEndToEndCommittedRestartRejectsChangedLedger(
	t *testing.T,
) {
	fixture := newRealCommittedCustodyFixture(t)

	captureDir := filepath.Join(
		fixture.StateDir, "usn-capture-"+realCustodyScopeID,
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
		path := filepath.Join(captureDir, entry.Name())
		if err := os.WriteFile(
			path, []byte(`{"version":"changed"}`), 0o600,
		); err != nil {
			t.Fatal(err)
		}
		changed = true
		break
	}
	if !changed {
		t.Fatal("committed source ledger not found")
	}

	_, err = InspectRawUSNCustodyRecoveryWithCommittedState(
		context.Background(),
		fixture.RawRoot,
		fixture.StageRoot,
		fixture.StateDir,
		realCustodySourceID,
	)
	if err == nil {
		t.Fatal("changed committed ledger accepted")
	}
	assertRealCustodyCopiesRetained(t, fixture)
}

func TestRawUSNEndToEndCommittedRestartRejectsConflictingReceipt(
	t *testing.T,
) {
	fixture := newRealCommittedCustodyFixture(t)

	receipt := fixture.Receipt
	receipt.SourceLedgerSHA256[0] = strings.Repeat("f", 64)
	var err error
	receipt.SHA256, err = sourceCustodyReceiptHash(receipt)
	if err != nil {
		t.Fatal(err)
	}

	path, err := generationSourceCustodyPath(
		fixture.SealedDir, realCustodyGenerationID,
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}

	// The rewritten receipt has a valid self-check SHA-256. It must still
	// fail against the independently recovered collector ledger.
	_, err = InspectRawUSNCustodyRecoveryWithCommittedState(
		context.Background(),
		fixture.RawRoot,
		fixture.StageRoot,
		fixture.StateDir,
		realCustodySourceID,
	)
	if !errors.Is(err, ErrGenerationSourceCustodyConflict) {
		t.Fatalf("conflicting valid-hash receipt accepted: %v", err)
	}
	assertRealCustodyCopiesRetained(t, fixture)
}

// assertRealCustodyCopiesRetained proves that tests never discard or promote
// source bytes as a side effect of custody recovery inspection.
func assertRealCustodyCopiesRetained(
	t *testing.T,
	fixture realCommittedCustodyFixture,
) {
	t.Helper()

	if _, err := os.Stat(fixture.Tombstone); err != nil {
		t.Fatalf("raw source tombstone missing: %v", err)
	}
	if _, err := os.Stat(fixture.SealedDir); err != nil {
		t.Fatalf("sealed replacement missing: %v", err)
	}
}
