// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	m1FS19 = "iss-fs-2019.iss.local"
	m1FS22 = "iss-fs-22.iss.local"
)

func TestM1QuarantinePersistsAcrossStoreInstances(
	t *testing.T,
) {
	root := m1PrivateQuarantineTestDir(t)

	first := m1QuarantineStore{Root: root}

	if err := first.Persist(
		m1FS19,
		"RECORDED_RECEIPT_INVALID",
		"generation-test-1",
		"immutable receipt is invalid",
	); err != nil {
		t.Fatal(err)
	}

	// Simulate process restart by discarding the original store
	// and independently opening persistent state from disk.
	second := m1QuarantineStore{Root: root}

	loaded, err := second.Load([]string{m1FS19, m1FS22})
	if err != nil {
		t.Fatal(err)
	}

	if len(loaded) != 1 ||
		loaded[m1FS19].SourceID != m1FS19 ||
		loaded[m1FS19].Reason !=
			"RECORDED_RECEIPT_INVALID" {
		t.Fatalf("quarantine not restored: %+v", loaded)
	}

	if _, quarantined := loaded[m1FS22]; quarantined {
		t.Fatal("healthy FS22 was unexpectedly quarantined")
	}

	// A repeated fault must not replace or erase the original marker.
	if err := second.Persist(
		m1FS19,
		"RELATIONAL_CONFLICT",
		"generation-test-2",
		"second conflict",
	); err != nil {
		t.Fatal(err)
	}

	again, err := second.Load([]string{m1FS19, m1FS22})
	if err != nil {
		t.Fatal(err)
	}

	if again[m1FS19].Reason !=
		"RECORDED_RECEIPT_INVALID" ||
		again[m1FS19].GenerationID !=
			"generation-test-1" {
		t.Fatal("existing quarantine marker was overwritten")
	}

	t.Log("PASS: FS2019 quarantine persisted across store reopen")
	t.Log("PASS: FS22 remained unquarantined")
	t.Log("PASS: Repeated fault could not replace marker")
}

func TestM1QuarantineRejectsUnexpectedState(t *testing.T) {
	root := m1PrivateQuarantineTestDir(t)
	store := m1QuarantineStore{Root: root}

	unexpected := filepath.Join(root, "unknown-state.txt")

	if err := os.WriteFile(
		unexpected, []byte("unexpected"), 0600,
	); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Load([]string{
		m1FS19, m1FS22,
	}); err == nil {
		t.Fatal("unexpected quarantine object accepted")
	}

	if err := os.Remove(unexpected); err != nil {
		t.Fatal(err)
	}

	if err := store.Persist(
		m1FS22,
		"RELATIONAL_CONFLICT",
		"generation-test",
		"relational identity disagreement",
	); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Load([]string{
		m1FS19,
	}); err == nil {
		t.Fatal("unknown enrolled-source marker was accepted")
	}

	path := filepath.Join(root, m1FS22+".json")

	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Load([]string{
		m1FS19, m1FS22,
	}); err == nil {
		t.Fatal("writable quarantine marker was accepted")
	}

	t.Log("PASS: Unexpected object rejected")
	t.Log("PASS: Unknown-source marker rejected")
	t.Log("PASS: Writable marker rejected")
}

func TestM1QuarantineRejectsUnsafeStorage(t *testing.T) {
	root := m1PrivateQuarantineTestDir(t)
	store := m1QuarantineStore{Root: root}

	if err := store.Persist(
		"../escape",
		"RELATIONAL_CONFLICT",
		"",
		"invalid source",
	); err == nil {
		t.Fatal("source path traversal accepted")
	}

	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Load([]string{
		m1FS19, m1FS22,
	}); err == nil {
		t.Fatal("nonprivate state root accepted")
	}

	t.Log("PASS: Source traversal rejected")
	t.Log("PASS: Nonprivate storage rejected")
}
