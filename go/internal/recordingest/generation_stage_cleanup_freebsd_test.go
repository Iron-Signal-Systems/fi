// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package recordingest

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestGenerationStageCleanupPreservesMarkerForRecovery verifies that failed
// artifact removal cannot erase the marker required for orphan reclamation.
func TestGenerationStageCleanupPreservesMarkerForRecovery(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-failure test requires an unprivileged account")
	}

	stage := filepath.Join(
		t.TempDir(),
		generationStagePrefix+"cleanup-failure",
	)

	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}

	lease, err := newGenerationStageLease(stage)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()

	blocked := filepath.Join(stage, "blocked")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(blocked, 0700)

	artifact := filepath.Join(blocked, "artifact.jsonl")
	if err := os.WriteFile(artifact, []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(blocked, 0500); err != nil {
		t.Fatal(err)
	}

	generation := &PreparedGeneration{
		stagedDirectory: stage,
		stageLease:      lease,
	}

	if err := generation.Close(); err == nil {
		t.Fatal("expected staged artifact removal to fail")
	}

	marker := filepath.Join(stage, generationStageLeaseName)
	if _, err := os.Lstat(marker); err != nil {
		t.Fatalf("ownership marker lost after failed cleanup: %v", err)
	}

	if err := os.Chmod(blocked, 0700); err != nil {
		t.Fatal(err)
	}

	old := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(stage, old, old); err != nil {
		t.Fatal(err)
	}

	reclaimed, err := reclaimOneGenerationStage(
		stage, time.Now(), 24*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reclaimed {
		t.Fatal("abandoned generation was not reclaimed")
	}

	if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging directory remains after reclamation: %v", err)
	}
}

// TestGenerationStageCleanupRestoresMarkerAfterRmdirFailure verifies that
// failure to remove the final directory leaves a reclaimable stage.
func TestGenerationStageCleanupRestoresMarkerAfterRmdirFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission test requires an unprivileged account")
	}

	root := t.TempDir()
	stage := filepath.Join(root, generationStagePrefix+"rmdir-failure")

	if err := os.Mkdir(stage, 0700); err != nil {
		t.Fatal(err)
	}

	lease, err := newGenerationStageLease(stage)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()

	// Removing the marker inside stage succeeds, but removing stage
	// from its read-only parent must fail.
	if err := os.Chmod(root, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(root, 0700)

	err = removeGenerationStageDirectory(stage)
	if err == nil {
		t.Fatal("expected final directory removal to fail")
	}

	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}

	marker := filepath.Join(stage, generationStageLeaseName)
	info, err := os.Lstat(marker)
	if err != nil {
		t.Fatalf("restored ownership marker missing: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatal("restored marker has incorrect properties")
	}

	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}

	old := time.Now().Add(-25 * time.Hour)
	if err := os.Chtimes(stage, old, old); err != nil {
		t.Fatal(err)
	}

	removed, err := ReclaimAbandonedGenerationStages(
		root, 24*time.Hour,
	)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("reclaimed %d stages; expected 1", removed)
	}

	if _, err := os.Lstat(stage); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stage remains after reclamation: %v", err)
	}
}
