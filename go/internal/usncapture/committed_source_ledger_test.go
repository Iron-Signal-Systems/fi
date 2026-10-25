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
)

func TestCommittedSourceLedgerRejectsAlteredReceipt(t *testing.T) {
	store, seg, corr, dir, manifests := sampleSpoolPublication(t, false, false)
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordSourceManifestLedger(seg, corr, dir); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitVerifiedSpool(seg, corr, dir, manifests); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.dir, "receipt-"+seg.Name)
	if err := os.WriteFile(path, []byte(`{"version":"unexpected"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.ReadCommittedSourceLedger(seg.Batch.StartUSN); found || !errors.Is(err, ErrConflict) {
		t.Fatalf("altered receipt accepted: found=%v err=%v", found, err)
	}
}

func TestCommittedSourceLedgerRejectsInvalidStartUSN(t *testing.T) {
	store, _ := exampleStore(t, DefaultMaxPendingBytes)
	if _, found, err := store.ReadCommittedSourceLedger("not-a-USN"); found || !errors.Is(err, ErrConflict) {
		t.Fatalf("invalid start accepted: found=%v err=%v", found, err)
	}
}

func TestCommittedSourceLedgerRejectsMissingCounterpart(t *testing.T) {
	store, seg, corr, dir, manifests := sampleSpoolPublication(t, false, false)
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordSourceManifestLedger(seg, corr, dir); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.ReadCommittedSourceLedger(seg.Batch.StartUSN); found || !errors.Is(err, ErrPublicationPending) {
		t.Fatalf("uncommitted ledger accepted: found=%v err=%v", found, err)
	}
	if err := store.CommitVerifiedSpool(seg, corr, dir, manifests); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(store.sourceManifestLedgerPath(seg)); err != nil {
		t.Fatal(err)
	}
	if _, found, err := store.ReadCommittedSourceLedger(seg.Batch.StartUSN); found || !errors.Is(err, ErrPublicationPending) {
		t.Fatalf("missing ledger accepted: found=%v err=%v", found, err)
	}
}

// Source-manifest custody remains queryable after the queue reclaims the
// original captured USN batch. The reader cannot advance any cursor.
func TestCommittedSourceLedgerSurvivesCaptureReclamation(t *testing.T) {
	store, seg, corr, dir, manifests := sampleSpoolPublication(t, false, false)
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	original, err := store.RecordSourceManifestLedger(seg, corr, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitVerifiedSpool(seg, corr, dir, manifests); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ReclaimAcknowledged(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(store.dir, seg.Name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original captured batch was not reclaimed: %v", err)
	}
	reopened, err := Open(store.dir, DefaultMaxPendingBytes)
	if err != nil {
		t.Fatal(err)
	}
	loaded, found, err := reopened.ReadCommittedSourceLedger(seg.Batch.StartUSN)
	if err != nil || !found || !reflect.DeepEqual(original, loaded) {
		t.Fatalf("committed ledger found=%t err=%v ledger=%+v", found, err, loaded)
	}
	if reopened.ProcessingCursor().NextUSN != seg.Batch.NextUSN {
		t.Fatal("read-only inventory lookup changed the processing cursor")
	}
}

func TestCommittedSourceLedgerSnapshotSurvivesBatchReclamation(t *testing.T) {
	store, seg, corr, dir, manifests := sampleSpoolPublication(t, false, false)
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	ledger, err := store.RecordSourceManifestLedger(seg, corr, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CommitVerifiedSpool(seg, corr, dir, manifests); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.ReclaimAcknowledged(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(store.dir, seg.Name)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("captured source batch not reclaimed: %v", err)
	}
	loaded, found, err := ReadCommittedSourceLedgerSnapshot(store.dir, seg.Batch.StartUSN)
	if err != nil || !found || !reflect.DeepEqual(ledger, loaded) {
		t.Fatalf("snapshot lookup found=%v err=%v ledger=%+v", found, err, loaded)
	}
	if store.ProcessingCursor().NextUSN != seg.Batch.NextUSN {
		t.Fatal("snapshot lookup changed collector cursor")
	}
}

func TestCommittedSourceLedgerSnapshotRejectsCursorCorruption(t *testing.T) {
	for _, mutate := range []struct {
		name  string
		apply func(*testing.T, *Store)
	}{
		{"absent-capture", func(t *testing.T, s *Store) {
			if err := os.Remove(filepath.Join(s.dir, captureName)); err != nil {
				t.Fatal(err)
			}
		}},
		{"malformed-processed", func(t *testing.T, s *Store) {
			if err := os.WriteFile(filepath.Join(s.dir, processedName), []byte("not-json"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"processed-ahead-of-capture", func(t *testing.T, s *Store) {
			cursor := s.ProcessingCursor()
			cursor.NextUSN = "999999"
			if err := os.WriteFile(filepath.Join(s.dir, processedName), mustJSON(cursor), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			store, _ := exampleStore(t, DefaultMaxPendingBytes)
			mutate.apply(t, store)
			if _, found, err := ReadCommittedSourceLedgerSnapshot(store.dir, "100"); found || err == nil {
				t.Fatalf("unsafe cursor snapshot was accepted: found=%v err=%v", found, err)
			}
		})
	}
}

func TestCommittedSourceLedgerSnapshotRejectsDirectoryAlias(t *testing.T) {
	store, _ := exampleStore(t, DefaultMaxPendingBytes)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(store.dir, alias); err != nil {
		t.Skipf("directory alias unavailable: %v", err)
	}
	if _, found, err := ReadCommittedSourceLedgerSnapshot(alias, "100"); found || !errors.Is(err, ErrCorrupt) {
		t.Fatalf("directory alias accepted: found=%v err=%v", found, err)
	}
}
