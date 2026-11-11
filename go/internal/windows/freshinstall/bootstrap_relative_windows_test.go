// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func bootstrapTestDescriptor(t *testing.T) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(nativeBootstrapSDDL)
	if err != nil {
		t.Fatal(err)
	}
	return descriptor
}

func bootstrapOpenParent(t *testing.T, directory string) windows.Handle {
	return bootstrapOpenParentWithSharing(t, directory, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
}

func bootstrapOpenParentWithSharing(t *testing.T, directory string, share uint32) windows.Handle {
	t.Helper()
	ptr, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		t.Fatal(err)
	}
	// The additional 0x4 is FILE_ADD_SUBDIRECTORY, required to request
	// a named creation under this directory rather than merely query it.
	parent, err := windows.CreateFile(
		ptr,
		windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES|0x00000004,
		share,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	return parent
}

func TestNativeBootstrapRelativeCreateRejectsInvalidInputs(t *testing.T) {
	descriptor := bootstrapTestDescriptor(t)
	for _, invalid := range []windows.Handle{0, windows.InvalidHandle} {
		if h, err := createProtectedBootstrapChildAt(invalid, descriptor); h != 0 || !errors.Is(err, ErrBootstrapInDoubt) {
			if h != 0 {
				_ = windows.CloseHandle(h)
			}
			t.Fatalf("invalid parent handle accepted: %v", err)
		}
	}
	parent := bootstrapOpenParent(t, t.TempDir())
	defer windows.CloseHandle(parent)
	if h, err := createProtectedBootstrapChildAt(parent, nil); h != 0 || !errors.Is(err, ErrBootstrapInDoubt) {
		if h != 0 {
			_ = windows.CloseHandle(h)
		}
		t.Fatalf("nil security descriptor accepted: %v", err)
	}
	unsafe, err := windows.SecurityDescriptorFromString("O:SYG:SYD:(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	if h, err := createProtectedBootstrapChildAt(parent, unsafe); h != 0 || !errors.Is(err, ErrBootstrapInDoubt) {
		if h != 0 {
			_ = windows.CloseHandle(h)
		}
		t.Fatalf("weak owner/DACL reached NtCreateFile: %v", err)
	}
}

func TestNativeBootstrapRelativeCreateBindsToHeldParentAfterRename(t *testing.T) {
	root := t.TempDir()
	original := filepath.Join(root, "original")
	moved := filepath.Join(root, "moved")
	if err := os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	// This test intentionally permits delete-sharing on its disposable
	// parent directory so the rename can succeed while the parent handle
	// remains live. Production never requests this sharing mode. The test
	// isolates whether RootDirectory, not a stale absolute name, determines
	// which parent object receives the new child.
	parent := bootstrapOpenParentWithSharing(
		t, original, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
	)
	defer windows.CloseHandle(parent)
	if err := os.Rename(original, moved); err != nil {
		t.Fatalf("test-only delete-sharing parent could not be relocated before native create: %v", err)
	}
	child, err := createProtectedBootstrapChildAt(parent, bootstrapTestDescriptor(t))
	if err != nil {
		// Exact protected owner assignment can be forbidden by runner token.
		// A failure after the rename is NOT accepted as successful creation.
		t.Fatalf("native creation under relocated retained parent failed: %v", err)
	}
	defer windows.CloseHandle(child)
	finalParent, err := nativeFinalPath(parent)
	if err != nil {
		t.Fatal(err)
	}
	finalChild, err := nativeFinalPath(child)
	if err != nil {
		t.Fatal(err)
	}
	if !sameNativePath(filepath.Dir(finalChild), finalParent) ||
		!strings.EqualFold(filepath.Base(finalChild), nativeBootstrapDirectoryName) {
		t.Fatalf("NtCreateFile child escaped retained parent: parent=%q child=%q", finalParent, finalChild)
	}
	if _, err := os.Lstat(filepath.Join(moved, nativeBootstrapDirectoryName)); err != nil {
		t.Fatalf("relative create did not follow held renamed parent object: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(original, nativeBootstrapDirectoryName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("relative create followed stale name instead of original handle: %v", err)
	}
	if err := verifyJournalParentHandle(child); err != nil {
		t.Fatalf("native created child lacks the protected descriptor: %v", err)
	}
}

func TestNativeBootstrapRelativeCreateRefusesClosedParentAndCollision(t *testing.T) {
	// Only a separate sandbox parent is used; no real FI owned paths or
	// running Windows services may be touched.
	parentPath := t.TempDir()
	parent := bootstrapOpenParent(t, parentPath)
	descriptor := bootstrapTestDescriptor(t)
	child, err := createProtectedBootstrapChildAt(parent, descriptor)
	if err != nil {
		_ = windows.CloseHandle(parent)
		t.Fatalf("initial fixed-name native creation failed: %v", err)
	}
	if err := windows.CloseHandle(child); err != nil {
		t.Fatal(err)
	}
	second, err := createProtectedBootstrapChildAt(parent, descriptor)
	if second != 0 {
		_ = windows.CloseHandle(second)
	}
	if !errors.Is(err, ErrBootstrapAlreadyExists) {
		t.Fatalf("FILE_CREATE adopted/overwrote existing child: %v", err)
	}
	if err := windows.CloseHandle(parent); err != nil {
		t.Fatal(err)
	}
	again, err := createProtectedBootstrapChildAt(parent, descriptor)
	if again != 0 {
		_ = windows.CloseHandle(again)
	}
	if err == nil {
		t.Fatal("closed native parent created a new FI directory")
	}
	if err := verifyJournalParentHandle(child); err == nil {
		// Handle is closed; a file security read cannot certify stale state.
		t.Fatal("closed child handle still authorized native owner/DACL")
	}
}
