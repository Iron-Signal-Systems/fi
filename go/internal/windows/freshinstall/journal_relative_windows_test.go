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

func openDisposableJournalParent(t *testing.T, path string, sharing uint32) windows.Handle {
	t.Helper()
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|nativeJournalParentAddFile,
		sharing,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	return handle
}

// Open one disposable directory object, rename it, then create the journal.
// RootDirectory must name the original handle's object, NOT a stale or
// attacker-replaced parent path. This test never accesses live FI paths.
func TestNativeJournalRelativeCreateUsesRetainedParentAfterRename(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "original")
	moved := filepath.Join(root, "moved")
	if err := os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	parent := openDisposableJournalParent(
		t, original, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
	)
	defer windows.CloseHandle(parent)
	if err := os.Rename(original, moved); err != nil {
		t.Fatalf("could not rename delete-sharing test parent: %v", err)
	}
	journal, err := createNativeJournalFileAt(parent)
	if err != nil {
		t.Fatalf("parent-relative native journal creation failed: %v", err)
	}
	defer windows.CloseHandle(journal)
	heldParentPath, err := nativeFinalPath(parent)
	if err != nil {
		t.Fatal(err)
	}
	heldJournalPath, err := nativeFinalPath(journal)
	if err != nil {
		t.Fatal(err)
	}
	if !sameNativePath(filepath.Dir(heldJournalPath), heldParentPath) ||
		filepath.Base(heldJournalPath) != nativeCreationJournalName {
		t.Fatalf("journal was not created beneath retained parent: %q / %q", heldParentPath, heldJournalPath)
	}
	if _, err := os.Lstat(filepath.Join(moved, nativeCreationJournalName)); err != nil {
		t.Fatalf("journal not found under renamed original parent: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(original, nativeCreationJournalName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal unexpectedly appeared at stale original name: %v", err)
	}
}

func TestNativeJournalRelativeCreateRejectsExistingAndInvalidParents(t *testing.T) {
	for _, bad := range []windows.Handle{0, windows.InvalidHandle} {
		child, err := createNativeJournalFileAt(bad)
		if child != 0 {
			_ = windows.CloseHandle(child)
		}
		if !errors.Is(err, ErrCreationInDoubt) {
			t.Fatalf("invalid native parent unexpectedly accepted: %v", err)
		}
	}
	parent := openDisposableJournalParent(t, t.TempDir(), windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
	first, err := createNativeJournalFileAt(parent)
	if err != nil {
		_ = windows.CloseHandle(parent)
		t.Fatalf("native create-new journal rejected on empty test directory: %v", err)
	}
	if err := windows.CloseHandle(first); err != nil {
		t.Fatal(err)
	}
	second, err := createNativeJournalFileAt(parent)
	if second != 0 {
		_ = windows.CloseHandle(second)
	}
	if !errors.Is(err, ErrCreationInDoubt) {
		t.Fatalf("journal FILE_CREATE adopted existing file: %v", err)
	}
	if err := windows.CloseHandle(parent); err != nil {
		t.Fatal(err)
	}
	afterClose, err := createNativeJournalFileAt(parent)
	if afterClose != 0 {
		_ = windows.CloseHandle(afterClose)
	}
	if !errors.Is(err, ErrCreationInDoubt) {
		t.Fatalf("closed parent handle accepted for creation: %v", err)
	}
}
