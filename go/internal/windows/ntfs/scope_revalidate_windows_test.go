// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestRevalidateScopeHandlesRejectsRootReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "governed")
	moved := filepath.Join(parent, "moved")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target.txt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	rootUnits := testPathUnits(t, root)
	targetUnits := testPathUnits(t, target)
	rootHandle, err := openPath(nulTerminate(rootUnits))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(rootHandle)
	targetHandle, err := openPath(nulTerminate(targetUnits))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(targetHandle)

	rootState, err := queryNativeState(rootHandle)
	if err != nil {
		t.Fatal(err)
	}
	targetState, err := queryNativeState(targetHandle)
	if err != nil {
		t.Fatal(err)
	}
	rootFinal, err := finalVolumePath(rootHandle)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := revalidateScopeHandles(rootHandle, targetHandle, rootUnits, rootFinal, rootState.ID, targetState.ID); err != nil {
		t.Fatalf("baseline revalidation failed: %v", err)
	}

	if err := os.Rename(root, moved); err != nil {
		t.Skipf("environment would not rename open NTFS directory: %v", err)
	}
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err = revalidateScopeHandles(rootHandle, targetHandle, rootUnits, rootFinal, rootState.ID, targetState.ID)
	if !errors.Is(err, ErrGovernedRootChangedDuringCollection) && !errors.Is(err, ErrOutsideGovernedRoot) {
		t.Fatalf("error = %v, want governed-root change or outside-root rejection", err)
	}
}

func TestVerifyWalkDirectoryIdentityRejectsPathReplacement(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "governed")
	moved := filepath.Join(parent, "moved")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}

	observation, err := CollectPath(nil, "scope-walk-race", root, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(root, moved); err != nil {
		t.Skipf("environment would not rename NTFS directory: %v", err)
	}
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}

	directory, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := verifyWalkDirectoryIdentity(directory, observation); !errors.Is(err, ErrWalkDirectoryChanged) {
		t.Fatalf("error = %v, want ErrWalkDirectoryChanged", err)
	}
}

func testPathUnits(t *testing.T, value string) []uint16 {
	t.Helper()
	units, err := syscall.UTF16FromString(value)
	if err != nil {
		t.Fatal(err)
	}
	return units[:len(units)-1]
}
