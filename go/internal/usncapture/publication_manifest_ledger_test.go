// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func TestM5BSourceLedgerFrozenRawSurvivesRetirementWithoutCommitting(t *testing.T) {
	s, seg, corr, dir, paths := sampleSpoolPublication(t, false, false)
	if err := s.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	raw := freezeTestSpool(t, dir)
	ledger, err := s.RecordSourceManifestLedger(seg, corr, dir)
	if err != nil || len(ledger.Manifests) != len(paths) || ledger.GenerationID != filepath.Base(raw) ||
		ledger.CustodyKind != PublicationCustodyFrozenRaw || ledger.SHA256 == "" {
		t.Fatalf("unexpected ledger %+v / %v", ledger, err)
	}
	if s.ProcessingCursor().NextUSN != "100" {
		t.Fatal("inventory advanced processed cursor")
	}
	if err := os.RemoveAll(raw); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(s.dir, DefaultMaxPendingBytes)
	if err != nil {
		t.Fatal(err)
	}
	loaded, found, err := restarted.ReadSourceManifestLedger(seg, corr)
	if err != nil || !found || !reflect.DeepEqual(loaded, ledger) {
		t.Fatalf("ledger lost across restart: %v %v %+v", found, err, loaded)
	}
	if _, err := restarted.RecordSourceManifestLedger(seg, corr, dir); !errors.Is(err, ErrPublicationPending) {
		t.Fatalf("retired originals wrongly treated as current custody proof: %v", err)
	}
	if restarted.ProcessingCursor().NextUSN != "100" {
		t.Fatal("inventory committed processing after retirement")
	}
}

func TestM5BSourceLedgerIdempotentAcrossRollover(t *testing.T) {
	s, seg, corr, dir, paths := sampleSpoolPublication(t, false, false)
	if err := s.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	original, err := s.RecordSourceManifestLedger(seg, corr, dir)
	if err != nil || original.CustodyKind != PublicationCustodyActive || len(original.Manifests) != len(paths) {
		t.Fatal(err)
	}
	duplicate, err := s.RecordSourceManifestLedger(seg, corr, dir)
	if err != nil || !reflect.DeepEqual(duplicate, original) {
		t.Fatalf("changed identical inventory: %v", err)
	}
	freezeTestSpool(t, dir)
	frozen, err := s.RecordSourceManifestLedger(seg, corr, dir)
	if err != nil || !reflect.DeepEqual(frozen, original) {
		t.Fatalf("rollover changed immutable anchor: %v", err)
	}
	if s.ProcessingCursor().NextUSN != "100" {
		t.Fatal("inventory committed processing")
	}
}

func TestM5BSourceLedgerRejectsTamperingAndWrongCorrelation(t *testing.T) {
	s, seg, corr, dir, _ := sampleSpoolPublication(t, false, false)
	if err := s.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordSourceManifestLedger(seg, corr, dir); err != nil {
		t.Fatal(err)
	}
	wrong := corr
	wrong.RootIdentity = corrID("777", "1")
	if _, _, err := s.ReadSourceManifestLedger(seg, wrong); !errors.Is(err, ErrConflict) {
		t.Fatalf("accepted wrong root: %v", err)
	}
	path := s.sourceManifestLedgerPath(seg)
	if err := os.WriteFile(path, []byte(`{"version":"bad"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ReadSourceManifestLedger(seg, corr); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered inventory accepted: %v", err)
	}
	if s.ProcessingCursor().NextUSN != "100" {
		t.Fatal("tampering advanced cursor")
	}
}

func TestM5BSourceLedgerRejectsUnverifiedPublicationAndSymlink(t *testing.T) {
	s, seg, corr, dir, paths := sampleSpoolPublication(t, false, false)
	if _, err := s.RecordSourceManifestLedger(seg, corr, dir); !errors.Is(err, ErrConflict) {
		t.Fatalf("no intent was accepted: %v", err)
	}
	if err := s.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	verified, err := spool.VerifyManifest(paths[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(verified.DataPath, []byte("invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecordSourceManifestLedger(seg, corr, dir); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("tampered FI spool accepted: %v", err)
	}
	if _, found, err := s.ReadSourceManifestLedger(seg, corr); err != nil || found {
		t.Fatalf("incomplete inventory published: %v %v", found, err)
	}
}

func TestM5BSourceLedgerCapacityIsSharedWithCaptureQueue(t *testing.T) {
	s, seg, corr, dir, _ := sampleSpoolPublication(t, false, false)
	if err := s.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	used, err := s.pendingBytesLocked()
	if err != nil {
		t.Fatal(err)
	}
	s.maxBytes = used + 1
	if _, err := s.RecordSourceManifestLedger(seg, corr, dir); !errors.Is(err, ErrCapacity) {
		t.Fatalf("source ledger bypassed disk budget: %v", err)
	}
	if _, found, err := s.ReadSourceManifestLedger(seg, corr); err != nil || found {
		t.Fatalf("over-budget ledger written: %v %v", found, err)
	}
}

// The Windows collector holds the publish boundary while recording the
// source-manifest ledger and committing the processing cursor. This test
// establishes the required ordering and its restart-persistent inventory.
func TestM5BActiveLedgerBeforeVerifiedProcessingCommit(t *testing.T) {
	s, seg, corr, dir, manifests := sampleSpoolPublication(t, false, false)
	if err := s.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}

	guard, err := spool.AcquirePublishBoundary()
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()

	ledger, err := s.RecordActiveSourceManifestLedger(seg, corr, dir, manifests)
	if err != nil {
		t.Fatal(err)
	}
	if ledger.CustodyKind != PublicationCustodyActive ||
		ledger.SourceBatchSHA256 != seg.SHA256 ||
		len(ledger.Manifests) != len(manifests) {
		t.Fatalf("incorrect active source inventory: %+v", ledger)
	}
	if s.ProcessingCursor().NextUSN != "100" {
		t.Fatal("recording a ledger advanced the processing cursor")
	}
	if err := s.CommitVerifiedSpool(seg, corr, dir, manifests); err != nil {
		t.Fatal(err)
	}
	if s.ProcessingCursor().NextUSN != "200" {
		t.Fatal("verified publication did not advance processing")
	}
	reopened, err := Open(s.dir, DefaultMaxPendingBytes)
	if err != nil {
		t.Fatal(err)
	}
	loaded, found, err := reopened.ReadSourceManifestLedger(seg, corr)
	if err != nil || !found || !reflect.DeepEqual(ledger, loaded) {
		t.Fatalf("durable source inventory not retained: found=%v err=%v", found, err)
	}
}

func TestM5BActiveLedgerRejectsDuplicateManifest(t *testing.T) {
	s, seg, corr, dir, manifests := sampleSpoolPublication(t, false, false)
	if err := s.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	guard, err := spool.AcquirePublishBoundary()
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Close()

	duplicate := append(append([]string(nil), manifests...), manifests[0])
	if _, err := s.RecordActiveSourceManifestLedger(seg, corr, dir, duplicate); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate source manifest accepted: %v", err)
	}
	if s.ProcessingCursor().NextUSN != "100" {
		t.Fatal("invalid inventory advanced the processing cursor")
	}
	if _, found, err := s.ReadSourceManifestLedger(seg, corr); err != nil || found {
		t.Fatalf("invalid inventory persisted: found=%v err=%v", found, err)
	}
}
