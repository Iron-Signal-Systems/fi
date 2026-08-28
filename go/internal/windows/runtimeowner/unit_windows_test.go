// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package runtimeowner

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestDefaultPathUsesFIStateDir(t *testing.T) {
	stateDir := t.TempDir()
	t.Setenv("FI_STATE_DIR", stateDir)

	got, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}

	want := filepath.Join(stateDir, DefaultLockFileName)
	if got != want {
		t.Fatalf("path = %q, want %q", got, want)
	}
}

func TestAcquirePathIsExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), DefaultLockFileName)

	first, err := AcquirePath(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	second, err := AcquirePath(path)
	if second != nil {
		_ = second.Close()
		t.Fatal("second ownership acquisition unexpectedly succeeded")
	}
	if !errors.Is(err, ErrAlreadyHeld) {
		t.Fatalf("error = %v, want ErrAlreadyHeld", err)
	}

	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	third, err := AcquirePath(path)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	if err := third.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOwnershipCloseIsIdempotent(t *testing.T) {
	ownership, err := AcquirePath(
		filepath.Join(t.TempDir(), DefaultLockFileName),
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := ownership.Close(); err != nil {
		t.Fatal(err)
	}
	if err := ownership.Close(); err != nil {
		t.Fatal(err)
	}
}
