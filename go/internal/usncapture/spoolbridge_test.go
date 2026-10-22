// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func sampleSpoolPublication(t *testing.T, omitOne, wrongRange bool) (*Store, Segment, Correlation, string, []string) {
	t.Helper()
	s, _ := exampleStore(t, DefaultMaxPendingBytes)
	if err := s.Append(sampleCorrelationBatch()); err != nil {
		t.Fatal(err)
	}
	seg, ok, err := s.Next()
	if !ok || err != nil {
		t.Fatal(err)
	}
	root := corrID("10", "1")
	corr, err := s.Correlate(seg, root)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writer, err := spool.NewWriter(dir, 3, spool.CollectorIdentity{
		ExecutablePath:   `C:\Program Files\FI\fi-collector.exe`,
		ExecutableSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatal(err)
	}
	boundary := SpoolBoundary{
		SourceBatchSHA256:         seg.SHA256,
		CorrelationSHA256:         corr.SHA256,
		RootIdentity:              root,
		JournalID:                 seg.Batch.JournalID,
		StartUSN:                  seg.Batch.StartUSN,
		NextUSN:                   seg.Batch.NextUSN,
		SourceRecordCount:         len(seg.Batch.Records),
		SourceDistinctObjectCount: len(seg.Work),
	}
	if wrongRange {
		boundary.StartUSN = "99"
	}
	if err := writer.Append("USNReadBoundary", seg.Batch.ScopeID, boundary); err != nil {
		t.Fatal(err)
	}
	changes := make(map[records.NTFSObjectIdentity][]records.USNChangeObservation)
	for _, change := range seg.Batch.Records {
		changes[change.FileIdentity] = append(changes[change.FileIdentity], change)
	}
	for i, work := range seg.Work {
		if omitOne && i == len(seg.Work)-1 {
			break
		}
		if err := writer.Append("USNObjectObservation", seg.Batch.ScopeID, struct {
			SourceBatchSHA256 string                         `json:"source_batch_sha256"`
			FileIdentity      records.NTFSObjectIdentity     `json:"file_identity"`
			Changes           []records.USNChangeObservation `json:"changes"`
			ScopeBasis        string                         `json:"scope_basis"`
			Status            string                         `json:"status"`
		}{seg.SHA256, work.FileIdentity, changes[work.FileIdentity], "ScopeUnresolvedIncluded", "Unavailable"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, batch := range writer.FinalizedBatches() {
		paths = append(paths, batch.ManifestPath)
	}
	return s, seg, corr, dir, paths
}

func TestVerifiedSpoolPublicationCommitsExactCapturedHistory(t *testing.T) {
	store, seg, corr, dir, paths := sampleSpoolPublication(t, false, false)
	if len(paths) < 2 {
		t.Fatal("test must exercise multi-manifest publication")
	}
	proof, err := VerifySpoolPublication(seg, corr, dir, paths)
	if err != nil || proof == "" {
		t.Fatalf("verify: %q %v", proof, err)
	}
	if store.ProcessingCursor().NextUSN != "100" {
		t.Fatal("verification advanced cursor")
	}
	if err := store.CommitVerifiedSpool(seg, corr, dir, paths); err != nil {
		t.Fatal(err)
	}
	if store.ProcessingCursor().NextUSN != "200" {
		t.Fatal("verified publication did not advance cursor")
	}
}

func TestVerifiedSpoolRejectsIncompleteCoverage(t *testing.T) {
	store, seg, corr, dir, paths := sampleSpoolPublication(t, true, false)
	if _, err := VerifySpoolPublication(seg, corr, dir, paths); !errors.Is(err, ErrConflict) {
		t.Fatalf("incomplete record coverage accepted: %v", err)
	}
	if store.ProcessingCursor().NextUSN != "100" {
		t.Fatal("cursor advanced on missing object")
	}
}

func TestVerifiedSpoolRejectsDifferentSourceBoundary(t *testing.T) {
	store, seg, corr, dir, paths := sampleSpoolPublication(t, false, true)
	if err := store.CommitVerifiedSpool(seg, corr, dir, paths); !errors.Is(err, ErrConflict) {
		t.Fatalf("unrelated boundary accepted: %v", err)
	}
	if store.ProcessingCursor().NextUSN != "100" {
		t.Fatal("cursor advanced on unrelated boundary")
	}
}

func TestVerifiedSpoolRejectsTamperedManifestedData(t *testing.T) {
	store, seg, corr, dir, paths := sampleSpoolPublication(t, false, false)
	manifest, err := spool.VerifyManifest(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(manifest.DataPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("tampered\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitVerifiedSpool(seg, corr, dir, paths); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered publication accepted: %v", err)
	}
}

func TestVerifiedSpoolRejectsMissingOrOutsideManifest(t *testing.T) {
	store, seg, corr, dir, paths := sampleSpoolPublication(t, false, false)
	if _, err := VerifySpoolPublication(seg, corr, dir, nil); err == nil {
		t.Fatal("missing spool proof")
	}
	outsider := filepath.Join(t.TempDir(), filepath.Base(paths[0]))
	if _, err := VerifySpoolPublication(seg, corr, dir, []string{outsider}); !errors.Is(err, ErrConflict) {
		t.Fatalf("unexpected external manifest error: %v", err)
	}
	if store.ProcessingCursor().NextUSN != "100" {
		t.Fatal("cursor advanced before valid proof")
	}
}

// The writer emits manifests beneath the physical publication directory, not
// necessarily the directory spelling supplied to NewWriter. Verify that the
// bridge accepts a configured alias without weakening outside-path checks.
func TestVerifiedSpoolPublicationAcceptsConfiguredDirectoryAlias(t *testing.T) {
	_, seg, corr, dir, paths := sampleSpoolPublication(t, false, false)
	alias := filepath.Join(t.TempDir(), "configured-spool-alias")
	if err := os.Symlink(dir, alias); err != nil {
		// Windows hosts without Developer Mode/symlink privilege cannot create
		// this alias. The ordinary TempDir publication test still runs there.
		t.Skipf("cannot create test directory alias: %v", err)
	}
	if proof, err := VerifySpoolPublication(seg, corr, alias, paths); err != nil || proof == "" {
		t.Fatalf("physical FI spool publication rejected behind alias: %q %v", proof, err)
	}
	if _, err := VerifySpoolPublication(seg, corr, alias, append(append([]string(nil), paths...), paths[0])); !errors.Is(err, ErrConflict) {
		t.Fatalf("repeated physical manifest accepted behind alias: %v", err)
	}
}
