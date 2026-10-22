// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func TestM5EPreflightMatchesCompleteCapturedRangeWithoutCommitting(t *testing.T) {
	s, seg, corr, raw, published := m5dSignedFixture(t)
	candidates := []PendingGenerationSource{{Segment: seg, Correlation: corr}}
	got, err := s.VerifyAndRecordGenerationPreflight(
		context.Background(), raw, published.DirectoryPath, "m5d-source", candidates,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SourceBatchSHA256 != seg.SHA256 ||
		got[0].GenerationID != published.Signed.Descriptor.GenerationID {
		t.Fatalf("wrong verified handoff %+v", got)
	}
	if s.CaptureCursor().NextUSN != "200" || s.ProcessingCursor().NextUSN != "100" {
		t.Fatal("preflight touched capture or processing cursor")
	}
	other, err := Open(s.dir, DefaultMaxPendingBytes)
	if err != nil {
		t.Fatal(err)
	}
	again, err := other.VerifyAndRecordGenerationPreflight(
		context.Background(), raw, published.DirectoryPath, "m5d-source", candidates,
	)
	if err != nil || len(again) != 1 || again[0] != got[0] {
		t.Fatalf("preflight changed after restart: %+v %v", again, err)
	}
}

func TestM5EPreflightRejectsMissingAndDuplicateSource(t *testing.T) {
	s, seg, corr, raw, published := m5dSignedFixture(t)
	candidate := PendingGenerationSource{Segment: seg, Correlation: corr}
	for _, tc := range []struct {
		name       string
		candidates []PendingGenerationSource
	}{
		{"no-candidates", nil},
		{"duplicate-source", []PendingGenerationSource{candidate, candidate}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.VerifyAndRecordGenerationPreflight(
				context.Background(), raw, published.DirectoryPath, "m5d-source", tc.candidates,
			)
			if !errors.Is(err, ErrConflict) {
				t.Fatalf("candidate coverage was accepted: %v", err)
			}
		})
	}
	if _, found, err := s.ReadSealedSourceHandoff(seg, corr); err != nil || found {
		t.Fatalf("failed preflight wrote receipt: %v %v", found, err)
	}
}

func TestM5EPreflightDetectsUnaccountedFrozenUSNBoundary(t *testing.T) {
	s, seg, corr, raw, published := m5dSignedFixture(t)
	writer, err := spool.NewWriter(raw, 10, spool.CollectorIdentity{
		ExecutablePath:   `C:\Program Files\FI\fi-collector.exe`,
		ExecutableSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Append("USNReadBoundary", seg.Batch.ScopeID, struct {
		SourceBatchSHA256 string `json:"source_batch_sha256"`
	}{"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = s.VerifyAndRecordGenerationPreflight(context.Background(), raw,
		published.DirectoryPath, "m5d-source", []PendingGenerationSource{{seg, corr}})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("missing source-bound candidate accepted: %v", err)
	}
	if _, found, err := s.ReadSealedSourceHandoff(seg, corr); err != nil || found {
		t.Fatalf("unverified handoff persisted: %v %v", found, err)
	}
}

func TestM5EPreflightRequiresFrozenOriginals(t *testing.T) {
	s, seg, corr, raw, published := m5dSignedFixture(t)
	if err := os.RemoveAll(raw); err != nil {
		t.Fatal(err)
	}
	_, err := s.VerifyAndRecordGenerationPreflight(context.Background(), raw,
		published.DirectoryPath, "m5d-source", []PendingGenerationSource{{seg, corr}})
	if err == nil {
		t.Fatal("sealed-only publication treated as original custody")
	}
	if _, found, err := s.ReadSealedSourceHandoff(seg, corr); err != nil || found {
		t.Fatalf("missing originals produced receipt: %v %v", found, err)
	}
}

func TestM5EPreflightHonorsContextAndWrongSource(t *testing.T) {
	s, seg, corr, raw, published := m5dSignedFixture(t)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.VerifyAndRecordGenerationPreflight(cancelled, raw, published.DirectoryPath,
		"m5d-source", []PendingGenerationSource{{seg, corr}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled generation accepted: %v", err)
	}
	_, err = s.VerifyAndRecordGenerationPreflight(context.Background(), raw, published.DirectoryPath,
		"wrong-source", []PendingGenerationSource{{seg, corr}})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong generation source accepted: %v", err)
	}
	if _, found, err := s.ReadSealedSourceHandoff(seg, corr); err != nil || found {
		t.Fatalf("preflight failure published handoff: %v %v", found, err)
	}
}

func TestM5EPreflightRejectsFrozenBoundaryWithoutSourceIdentity(t *testing.T) {
	dir := t.TempDir()
	writer, err := spool.NewWriter(dir, 10, spool.CollectorIdentity{
		ExecutablePath:   `C:\Program Files\FI\fi-collector.exe`,
		ExecutableSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Append("USNReadBoundary", "root-test", struct {
		StartUSN string `json:"start_usn"`
	}{"100"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	boundary, err := enumerateFrozenCapturedBoundaries(context.Background(), dir)
	if !errors.Is(err, ErrConflict) || boundary != nil {
		t.Fatalf("unattributed USN boundary accepted: %+v %v", boundary, err)
	}
}

func TestM5EPreflightDoesNotTrustDirectoryAliasAsSource(t *testing.T) {
	s, seg, corr, raw, published := m5dSignedFixture(t)
	alias := filepath.Join(t.TempDir(), "raw-alias")
	if err := os.Symlink(raw, alias); err != nil {
		t.Skipf("cannot create test directory link: %v", err)
	}
	_, err := s.VerifyAndRecordGenerationPreflight(context.Background(), alias,
		published.DirectoryPath, "m5d-source", []PendingGenerationSource{{seg, corr}})
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("symlink source accepted: %v", err)
	}
}
