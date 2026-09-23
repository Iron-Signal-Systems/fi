// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package workerlock

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAcquireRejectsRelativePath(t *testing.T) {
	if _, err := Acquire("worker.lock"); err == nil {
		t.Fatal("relative singleton lock path was accepted")
	}
}

func TestAcquireRejectsWritableParent(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}

	if _, err := Acquire(filepath.Join(root, "worker.lock")); err == nil {
		t.Fatal("group/other-writable singleton lock parent was accepted")
	}
}

func TestAcquireSingletonAndRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker.lock")

	first, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}

	second, err := Acquire(path)
	if second != nil {
		_ = second.Close()
		t.Fatal("second singleton lock owner was returned")
	}
	if !errors.Is(err, ErrAlreadyHeld) {
		t.Fatalf("second Acquire() error = %v, want ErrAlreadyHeld", err)
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	third, err := Acquire(path)
	if err != nil {
		t.Fatalf("Acquire() after release error = %v", err)
	}
	defer third.Close()

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("lock mode = %v, want 0600 regular file", info.Mode())
	}
}
