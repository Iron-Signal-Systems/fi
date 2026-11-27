// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package recordingest

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGenerationStageOwnershipAndReclamation(t *testing.T) {
	root := t.TempDir()
	active, err := os.MkdirTemp(root, generationStagePrefix+"*")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := newGenerationStageLease(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(active, "batch-test.jsonl"), []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}

	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(active, old, old); err != nil {
		t.Fatal(err)
	}
	removed, err := ReclaimAbandonedGenerationStages(root, 24*time.Hour)
	if err != nil || removed != 0 {
		t.Fatalf("active stage reclaimed: count=%d err=%v", removed, err)
	}
	if _, err := os.Stat(active); err != nil {
		t.Fatalf("active stage missing: %v", err)
	}

	// Simulate process death by releasing the FD without normal directory
	// cleanup. The held lock must stop reclamation; the released lock must
	// permit it once the stage is old enough.
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	removed, err = ReclaimAbandonedGenerationStages(root, 24*time.Hour)
	if err != nil || removed != 1 {
		t.Fatalf("abandoned stage not reclaimed: count=%d err=%v", removed, err)
	}
	if _, err := os.Lstat(active); !os.IsNotExist(err) {
		t.Fatalf("abandoned stage still exists: %v", err)
	}
}

func TestGenerationStageReclamationSkipsUnmarkedAndUnsafeEntries(t *testing.T) {
	root := t.TempDir()
	old := time.Now().Add(-48 * time.Hour)
	legacy, err := os.MkdirTemp(root, generationStagePrefix+"*")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(legacy, old, old); err != nil {
		t.Fatal(err)
	}

	external := t.TempDir()
	link := filepath.Join(root, generationStagePrefix+"fake-link")
	if err := os.Symlink(external, link); err != nil {
		t.Fatal(err)
	}

	fresh, err := os.MkdirTemp(root, generationStagePrefix+"*")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := newGenerationStageLease(fresh)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()

	removed, err := ReclaimAbandonedGenerationStages(root, 24*time.Hour)
	if err != nil || removed != 0 {
		t.Fatalf("unsafe/fresh entry reclaimed: count=%d err=%v", removed, err)
	}
	for _, path := range []string{legacy, fresh, link, external} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("unsafe/fresh path %q changed: %v", path, err)
		}
	}
	if _, err := ReclaimAbandonedGenerationStages(root, time.Minute); err == nil {
		t.Fatal("accepted unsafe one-minute cleanup grace")
	}
}
