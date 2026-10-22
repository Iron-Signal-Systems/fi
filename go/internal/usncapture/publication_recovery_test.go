// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func TestInterruptedSpoolPublisherRecoversExactSourceWithoutRewriting(t *testing.T) {
	store, seg, corr, dir, _ := sampleSpoolPublication(t, false, false)
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(store.dir, DefaultMaxPendingBytes)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.ProcessingCursor().NextUSN != "100" {
		t.Fatal("restart moved processed cursor")
	}
	calls := 0
	restored, err := reopened.RecoverPendingSpoolPublication(seg, corr, dir,
		func(paths []string) error {
			calls++
			if len(paths) < 2 {
				t.Fatal("expected all multi-batch manifests")
			}
			return nil
		})
	if err != nil || !restored || calls != 1 {
		t.Fatalf("recovery restored=%v calls=%d err=%v", restored, calls, err)
	}
	if reopened.ProcessingCursor().NextUSN != "200" {
		t.Fatal("verified restart did not commit")
	}
	if err := reopened.BeginSpoolPublication(seg, corr); !errors.Is(err, ErrConflict) {
		t.Fatalf("replayed consumed range: %v", err)
	}
}

func TestPendingPublicationWithRolloverNeverBlindlyRepublishes(t *testing.T) {
	store, seg, corr, _, paths := sampleSpoolPublication(t, false, false)
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	emptySpool := t.TempDir() // simulate sender rollover/retirement
	restored, err := store.RecoverPendingSpoolPublication(seg, corr, emptySpool, func([]string) error { return nil })
	if restored || !errors.Is(err, ErrPublicationPending) {
		t.Fatalf("missing original publication accepted: %v", err)
	}
	if err := store.BeginSpoolPublication(seg, corr); !errors.Is(err, ErrPublicationPending) {
		t.Fatalf("started duplicate publication: %v", err)
	}
	if store.ProcessingCursor().NextUSN != "100" {
		t.Fatal("cursor advanced without publication")
	}
	if len(paths) < 2 {
		t.Fatal("invalid fixture")
	}
}

func TestPublicationRecoveryPreservesSIDReconciliationFailure(t *testing.T) {
	store, seg, corr, dir, _ := sampleSpoolPublication(t, false, false)
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	failed := errors.New("SID state unavailable")
	restored, err := store.RecoverPendingSpoolPublication(seg, corr, dir, func([]string) error { return failed })
	if restored || !errors.Is(err, failed) {
		t.Fatalf("premature success: %v", err)
	}
	if store.ProcessingCursor().NextUSN != "100" {
		t.Fatal("SID failure advanced processing")
	}
	restored, err = store.RecoverPendingSpoolPublication(seg, corr, dir, func([]string) error { return nil })
	if err != nil || !restored {
		t.Fatalf("verified retry failed: %v", err)
	}
}

func TestCorruptPublishedManifestFailsClosedDuringRecovery(t *testing.T) {
	store, seg, corr, dir, paths := sampleSpoolPublication(t, false, false)
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths[0], []byte("broken manifest"), 0600); err != nil {
		t.Fatal(err)
	}
	restored, err := store.RecoverPendingSpoolPublication(seg, corr, dir, func([]string) error { t.Fatal("should not enter reconciliation"); return nil })
	if restored || !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt publication accepted: %v", err)
	}
	if store.ProcessingCursor().NextUSN != "100" {
		t.Fatal("corrupted spool advanced cursor")
	}
}

func TestIntentMismatchAndTamperingFailClosed(t *testing.T) {
	store, seg, corr, _, _ := sampleSpoolPublication(t, false, false)
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	wrong := corr
	wrong.RootIdentity = corrID("777", "1")
	if _, err := store.PublicationPending(seg, wrong); !errors.Is(err, ErrConflict) {
		t.Fatalf("accepted wrong identity: %v", err)
	}
	if err := os.WriteFile(filepath.Join(store.dir, "publication-"+seg.Name), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.PublicationPending(seg, corr); !errors.Is(err, ErrConflict) {
		t.Fatalf("tampered publication accepted: %v", err)
	}
}

func TestNewIntentWithoutSpoolPublicationCannotBeReplayed(t *testing.T) {
	store, _ := exampleStore(t, DefaultMaxPendingBytes)
	if err := store.Append(sampleCorrelationBatch()); err != nil {
		t.Fatal(err)
	}
	seg, ok, err := store.Next()
	if err != nil || !ok {
		t.Fatal(err)
	}
	corr, err := store.Correlate(seg, corrID("10", "1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	reopen, err := Open(store.dir, DefaultMaxPendingBytes)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := reopen.PublicationPending(seg, corr)
	if err != nil || !pending {
		t.Fatalf("lost durable intent: %v", err)
	}
	_, err = reopen.RecoverPendingSpoolPublication(seg, corr, t.TempDir(), func([]string) error { return nil })
	if !errors.Is(err, ErrPublicationPending) {
		t.Fatalf("accepted absence of spool: %v", err)
	}
}

func TestRecoveryRejectsMixedSourceManifest(t *testing.T) {
	store, seg, corr, dir, _ := sampleSpoolPublication(t, false, false)
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	writer, err := spool.NewWriter(dir, 10, spool.CollectorIdentity{
		ExecutablePath:   `C:\Program Files\FI\fi-collector.exe`,
		ExecutableSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{seg.SHA256, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"} {
		if err := writer.Append("USNObjectObservation", seg.Batch.ScopeID, struct {
			SourceBatchSHA256 string `json:"source_batch_sha256"`
		}{source}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := store.RecoverPendingSpoolPublication(seg, corr, dir, func([]string) error { return nil })
	if restored || !errors.Is(err, ErrConflict) {
		t.Fatalf("accepted mixed-source manifest: %v", err)
	}
}

func TestRecoveryIgnoresUnrelatedValidSpoolManifest(t *testing.T) {
	store, seg, corr, dir, originals := sampleSpoolPublication(t, false, false)
	if err := store.BeginSpoolPublication(seg, corr); err != nil {
		t.Fatal(err)
	}
	writer, err := spool.NewWriter(dir, 10, spool.CollectorIdentity{
		ExecutablePath:   `C:\Program Files\FI\fi-collector.exe`,
		ExecutableSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Append("WindowsSecurityEvent", "windows-security-local", struct {
		Irrelevant string `json:"irrelevant"`
	}{"unrelated"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := store.RecoverPendingSpoolPublication(seg, corr, dir, func(paths []string) error {
		if len(paths) != len(originals) {
			t.Fatalf("mixed in unrelated FI records: %d", len(paths))
		}
		return nil
	})
	if err != nil || !restored {
		t.Fatalf("failed to ignore unrelated batch: %v", err)
	}
}
