// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// These tests use fresh temporary directories only. They never read or
// change the host's actual FI installation state or Windows audit settings.
func TestWindowsSACLStartupNoFIOnFreshHost(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	if err := RecoverPendingWindowsSACLTransactions(); err != nil {
		t.Fatalf("fresh host should have no SACL recovery state: %v", err)
	}
}

func TestWindowsSACLStartupExistingFIRootWithoutStateFailsClosed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ProgramData", dir)
	if err := os.Mkdir(filepath.Join(dir, "FI"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RecoverPendingWindowsSACLTransactions(); err == nil {
		t.Fatal("existing FI root with missing persistent state accepted")
	}
}

func TestWindowsSACLStartupEmptyStateIsSafe(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ProgramData", dir)
	if err := os.MkdirAll(filepath.Join(dir, "FI", "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RecoverPendingWindowsSACLTransactions(); err != nil {
		t.Fatalf("empty FI state should have no pending SACL journal: %v", err)
	}
}

func TestWindowsSACLStartupIncompleteMarkerFailsClosed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ProgramData", dir)
	state := filepath.Join(dir, "FI", "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(state, fiSACLJournalPrefix+"truncated.incomplete")
	if err := os.WriteFile(marker, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := RecoverPendingWindowsSACLTransactions()
	if err == nil || !strings.Contains(err.Error(), "incomplete SACL journal") {
		t.Fatalf("truncated journal must block startup, got: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("failed recovery must retain marker: %v", err)
	}
}

func TestWindowsSACLStartupCorruptCompleteJournalFailsClosed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ProgramData", dir)
	state := filepath.Join(dir, "FI", "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	journal := filepath.Join(state, fiSACLJournalPrefix+"corrupt.json")
	if err := os.WriteFile(journal, []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := RecoverPendingWindowsSACLTransactions()
	if err == nil || !strings.Contains(err.Error(), "legacy SACL rollback journal requires investigation") {
		t.Fatalf("corrupt complete journal must block startup, got: %v", err)
	}
	if _, err := os.Stat(journal); err != nil {
		t.Fatalf("failed recovery must retain journal: %v", err)
	}
}

func TestWindowsSACLStartupMultipleArtifactsFailsBeforeMutation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ProgramData", dir)
	state := filepath.Join(dir, "FI", "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{fiSACLJournalPrefix + "first.json", fiSACLJournalPrefix + "second.incomplete"} {
		if err := os.WriteFile(filepath.Join(state, name), []byte("not-json"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err := RecoverPendingWindowsSACLTransactions()
	if err == nil || !strings.Contains(err.Error(), "multiple SACL rollback artifacts") {
		t.Fatalf("multiple rollback artifacts must block without changing SACL: %v", err)
	}
}

// A syntactically valid legacy rollback journal must not authorize Windows
// security descriptor mutation on startup. Recovery is now a read-only gate.
func TestWindowsSACLStartupValidLegacyJournalNotReplayed(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("ProgramData", dir)
	state := filepath.Join(dir, "FI", "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	journal := fiSACLJournal{
		Version: fiSACLJournalVersion, TransactionID: "20261016T090000.000000000Z",
		Roots:   []string{`C:\Nonexistent`},
		Entries: []fiSACLJournalEntry{{Path: `C:\Nonexistent`, SDDL: "S:"}},
	}
	checksum, err := fiSACLJournalChecksum(journal)
	if err != nil {
		t.Fatal(err)
	}
	bytes, err := json.Marshal(fiSACLJournalFile{SHA256: checksum, Journal: journal})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, fiSACLJournalPrefix+journal.TransactionID+".json")
	if err := os.WriteFile(path, bytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RecoverPendingWindowsSACLTransactions(); err == nil || !strings.Contains(err.Error(), "legacy SACL rollback journal") {
		t.Fatalf("legacy preimage must block without restore: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("legacy journal unexpectedly removed: %v", err)
	}
}
