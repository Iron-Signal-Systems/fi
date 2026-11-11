// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// Actual OS test is read-only: no FI files, service, ACL, registry or
// ProgramData children are created or modified on the Windows runner.
func TestNativeRootRelativeProgramDataMatchesObservedSystemDirectory(t *testing.T) {
	observed, err := inspectNativeSystemProgramData()
	if err != nil {
		t.Fatalf("read-only native Windows ProgramData observation: %v", err)
	}
	defer observed.Close()
	if err := observed.verifyRootRelativeProgramData(); err != nil {
		t.Fatalf("root-relative native ProgramData differs from independently observed OS object: %v", err)
	}
}

// This fixture preserves a HANDLE to an original root that is later
// renamed. The new absolute path is populated by another root with its
// own ProgramData. RootDirectory must follow the ORIGINAL root object.
func TestNativeRootRelativeProgramDataUsesRetainedRootAfterRelocation(t *testing.T) {
	parent := t.TempDir()
	original := filepath.Join(parent, "original")
	moved := filepath.Join(parent, "moved")
	if err := os.MkdirAll(filepath.Join(original, "ProgramData"), 0700); err != nil { t.Fatal(err) }
	root, err := openNativeSystemDirectoryWithSharing(original,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if err != nil { t.Fatal(err) }
	defer windows.CloseHandle(root.handle)
	initial, err := openNativeProgramDataFromRoot(root.handle)
	if err != nil { t.Fatal(err) }
	originalID := initial.id
	if err := initial.CloseHandle(); err != nil { t.Fatal(err) }

	if err := os.Rename(original, moved); err != nil {
		t.Fatalf("test cannot relocate original opened directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(original, "ProgramData"), 0700); err != nil { t.Fatal(err) }
	heldChild, err := openNativeProgramDataFromRoot(root.handle)
	if err != nil { t.Fatal(err) }
	defer heldChild.CloseHandle()
	if heldChild.id != originalID ||
		!sameNativePath(filepath.Dir(heldChild.nativePath), filepath.Join(parent, "moved")) {
		t.Fatalf("root-relative opening escaped the original retained root: %+v", heldChild.id)
	}
	other, err := openNativeSystemDirectory(filepath.Join(original, "ProgramData"))
	if err != nil { t.Fatal(err) }
	defer windows.CloseHandle(other.handle)
	if other.id == heldChild.id {
		t.Fatal("stale path replacement had same identity as original root-relative child")
	}
}

func TestNativeRootRelativeProgramDataRejectsMissingAndClosedRootHandles(t *testing.T) {
	for _, handle := range []windows.Handle{0, windows.InvalidHandle} {
		open, err := openNativeProgramDataFromRoot(handle)
		if open.handle != 0 { _ = open.CloseHandle() }
		if !errors.Is(err, ErrUnattestedSystemParent) {
			t.Fatalf("unusable native root accepted: %v", err)
		}
	}
	root, err := openNativeSystemDirectory(t.TempDir())
	if err != nil { t.Fatal(err) }
	if err := windows.CloseHandle(root.handle); err != nil { t.Fatal(err) }
	open, err := openNativeProgramDataFromRoot(root.handle)
	if open.handle != 0 { _ = open.CloseHandle() }
	if !errors.Is(err, ErrUnattestedSystemParent) {
		t.Fatalf("closed root handle accepted: %v", err)
	}

	// Do not create the required leaf: FILE_OPEN must never make it.
	empty, err := openNativeSystemDirectory(t.TempDir())
	if err != nil { t.Fatal(err) }
	defer windows.CloseHandle(empty.handle)
	open, err = openNativeProgramDataFromRoot(empty.handle)
	if open.handle != 0 { _ = open.CloseHandle() }
	if !errors.Is(err, ErrUnattestedSystemParent) {
		t.Fatalf("nonexistent ProgramData was created or accepted: %v", err)
	}
}

func TestNativeRootRelativeProgramDataRefusesReparseLeaf(t *testing.T) {
	root := t.TempDir()
	actual := filepath.Join(root, "actual")
	alias := filepath.Join(root, "ProgramData")
	if err := os.Mkdir(actual, 0700); err != nil { t.Fatal(err) }
	if err := os.Symlink(actual, alias); err != nil {
		t.Skipf("native runner cannot create isolated Windows reparse fixture: %v", err)
	}
	dir, err := openNativeSystemDirectory(root)
	if err != nil { t.Fatal(err) }
	defer windows.CloseHandle(dir.handle)
	child, err := openNativeProgramDataFromRoot(dir.handle)
	if child.handle != 0 { _ = child.CloseHandle() }
	if !errors.Is(err, ErrUnattestedSystemParent) {
		t.Fatalf("ProgramData reparse alias was accepted: %v", err)
	}
}
