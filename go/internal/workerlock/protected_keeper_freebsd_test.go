// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package workerlock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func keeperProtectedLockFixture(t *testing.T) (string, ProtectedLockPolicy, uint32) {
	t.Helper()
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Skip("requires non-root UID/GID")
	}
	parent := t.TempDir()
	directory := filepath.Join(parent, "keeper")
	if err := os.Mkdir(directory, 0710); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(directory, -1, os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0710); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, ProtectedLockName)
	if err := os.WriteFile(path, nil, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, -1, os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	policy := ProtectedLockPolicy{
		KeeperUID: uint32(os.Geteuid()), WorkerUID: uint32(os.Geteuid() + 1), WorkerGID: uint32(os.Getegid()),
	}
	return directory, policy, uint32(os.Getegid())
}

func TestKeeperProtectedLockRejectsFalseIdentity(t *testing.T) {
	directory, policy, keeperGID := keeperProtectedLockFixture(t)
	invalid := policy
	invalid.KeeperUID = policy.WorkerUID
	if _, err := acquireProtectedAsKeeperAt(directory, invalid, keeperGID); err == nil {
		t.Fatal("untrusted keeper UID accepted")
	}
	invalid = policy
	invalid.WorkerUID = policy.KeeperUID
	if _, err := acquireProtectedAsKeeperAt(directory, invalid, keeperGID); err == nil {
		t.Fatal("keeper and worker UID allowed to coincide")
	}
}

func TestKeeperProtectedLockExclusiveAndNoFallback(t *testing.T) {
	directory, policy, keeperGID := keeperProtectedLockFixture(t)
	first, err := acquireProtectedAsKeeperAt(directory, policy, keeperGID)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := acquireProtectedAsKeeperAt(directory, policy, keeperGID)
	if !errors.Is(err, ErrAlreadyHeld) {
		if second != nil {
			_ = second.Close()
		}
		t.Fatalf("simultaneous release lock allowed or unexpected error: %v", err)
	}
	if err := os.Remove(filepath.Join(directory, ProtectedLockName)); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireProtectedAsKeeperAt(directory, policy, keeperGID); err == nil {
		t.Fatal("keeper lock recreated after pathname deletion")
	}
}

func TestKeeperProtectedLockRejectsIncorrectMode(t *testing.T) {
	directory, policy, keeperGID := keeperProtectedLockFixture(t)
	path := filepath.Join(directory, ProtectedLockName)
	if err := os.Chmod(path, 0660); err != nil {
		t.Fatal(err)
	}
	if lock, err := acquireProtectedAsKeeperAt(directory, policy, keeperGID); err == nil {
		_ = lock.Close()
		t.Fatal("writable protected lock accepted")
	}
}
