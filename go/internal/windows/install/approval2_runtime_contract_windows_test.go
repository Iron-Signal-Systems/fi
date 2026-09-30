// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateGovernedRootsForInstallAcceptsExistingDirectory(t *testing.T) {
	root := t.TempDir()

	if err := ValidateGovernedRootsForInstall([]string{root}); err != nil {
		t.Fatalf("existing governed root rejected: %v", err)
	}
}

func TestValidateGovernedRootsForInstallRejectsMissingDirectory(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")

	err := ValidateGovernedRootsForInstall([]string{root})
	if err == nil {
		t.Fatal("missing governed root unexpectedly accepted")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateGovernedRootsForInstallRejectsFile(t *testing.T) {
	root := filepath.Join(t.TempDir(), "not-a-directory.txt")
	if err := os.WriteFile(root, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := ValidateGovernedRootsForInstall([]string{root})
	if err == nil {
		t.Fatal("file governed root unexpectedly accepted")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPlanLocalGroupsRequiresCollectorEventLogReaders(t *testing.T) {
	identities := DesiredFIIdentities{
		CollectorSender: DesiredFIIdentity{
			Account: `ISS\gFI-ADMINBOX$`,
			Role:    "FICollector/FISender",
		},
		USNReader: DesiredFIIdentity{
			Account: `ISS\gFI-USN-ADMINBOX$`,
			Role:    "FIUSNReader",
		},
		ObjReader: DesiredFIIdentity{
			Account: `ISS\gFI-OBJ-ADMINBOX$`,
			Role:    "FIObjReader",
		},
	}

	var plan InstallPlan
	planLocalGroups(
		&plan,
		Report{},
		identities,
		nil,
	)

	target := identities.CollectorSender.Account + " -> Event Log Readers"
	for _, action := range plan.Actions {
		if action.Authority != "GROUPS" || action.Target != target {
			continue
		}
		if action.Action != planActionReconcile {
			t.Fatalf(
				"Event Log Readers action=%q want=%q",
				action.Action,
				planActionReconcile,
			)
		}
		if !strings.Contains(action.Detail, "add direct membership") {
			t.Fatalf("unexpected Event Log Readers detail: %s", action.Detail)
		}
		return
	}

	t.Fatalf("missing GROUPS action for %s", target)
}

func TestRollbackApproval2CreatedDirectoriesRemovesPopulatedTree(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "FI")
	state := filepath.Join(root, "state")

	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(state, "service-runtime.jsonl"),
		[]byte("{}\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}

	if err := rollbackApproval2CreatedDirectories(
		[]string{root, state},
	); err != nil {
		t.Fatalf("rollback populated transaction tree: %v", err)
	}

	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("transaction-created root still exists; stat err=%v", err)
	}
}
