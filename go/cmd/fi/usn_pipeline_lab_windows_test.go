// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUSNPipelineLabRequiresExactOptIn(t *testing.T) {
	t.Setenv(labPipelineEnv, "")
	enabled, err := labPipelineRequested()
	if err != nil || enabled {
		t.Fatalf("unexpected default: %t %v", enabled, err)
	}
	t.Setenv(labPipelineEnv, "1")
	enabled, err = labPipelineRequested()
	if err != nil || !enabled {
		t.Fatalf("explicit lab enable rejected: %t %v", enabled, err)
	}
	t.Setenv(labPipelineEnv, "true")
	if _, err = labPipelineRequested(); err == nil {
		t.Fatal("ambiguous lab opt-in accepted")
	}
}

func TestUSNPipelineLabQueueNamesAreContained(t *testing.T) {
	state := t.TempDir()
	queue, err := labPipelineQueueDir(state, "root-0123456789")
	if err != nil || queue != filepath.Join(state, labQueuePrefix+"root-0123456789") {
		t.Fatalf("invalid queue path: %q %v", queue, err)
	}
	for _, scope := range []string{"", "..", "root/a", `root\a`, "root:a"} {
		if _, err := labPipelineQueueDir(state, scope); err == nil {
			t.Fatalf("accepted invalid scope %q", scope)
		}
	}
}

func TestUSNPipelineLabLegacyGuardFailsClosed(t *testing.T) {
	state := t.TempDir()
	t.Setenv("FI_STATE_DIR", state)
	root := `F:\FI-GOVERNED-TEST`
	if err := guardLegacyUSNRoot(root); err != nil {
		t.Fatalf("empty legacy state blocked: %v", err)
	}
	scope := configuredScopeID(root)
	queue, err := labPipelineQueueDir(state, scope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(queue, 0700); err != nil {
		t.Fatal(err)
	}
	if err := guardLegacyUSNRoot(root); err == nil || !strings.Contains(err.Error(), "legacy") {
		t.Fatalf("legacy checkpoint owner was not blocked: %v", err)
	}
	if err := os.Remove(queue); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestUSNPipelineLabRootLoopDoesNotClaimCollection(t *testing.T) {
	summary := writeLabRootCollectionSummary(serviceOperationalSnapshot{GovernedRoots: []string{`F:\GOVERNED`}})
	if summary.Complete || summary.CompletedRoots != 0 || summary.PartialRoots != 1 {
		t.Fatalf("inactive legacy collector falsely reports complete: %+v", summary)
	}
}
