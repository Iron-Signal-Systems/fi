// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This helper is test-only. The caller MUST use a disposable directory,
// never the actual system ProgramData or a real FI-owned path.
func makeTestDirectoryAtNativeHandle(parent windows.Handle) (windows.Handle, error) {
	name, err := windows.NewNTUnicodeString("test-only-create-child")
	if err != nil { return 0, err }
	oa := &windows.OBJECT_ATTRIBUTES{
		Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName: name,
		Attributes: windows.OBJ_CASE_INSENSITIVE|windows.OBJ_DONT_REPARSE,
	}
	var child windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&child,
		windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		oa, &iosb, nil,
		windows.FILE_ATTRIBUTE_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		windows.FILE_CREATE,
		windows.FILE_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	runtime.KeepAlive(name)
	if err != nil { return 0, err }
	if child == 0 || child == windows.InvalidHandle || iosb.Information != uintptr(nativeDirectoryCreated) {
		if child != 0 && child != windows.InvalidHandle { _ = windows.CloseHandle(child) }
		return 0, ErrBootstrapInDoubt
	}
	return child, nil
}

func TestNativeRootRelativeProgramDataCreateRightIsLimitedToDisposableDirectory(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "ProgramData"), 0700); err != nil { t.Fatal(err) }
	original, err := openNativeSystemDirectory(root)
	if err != nil { t.Fatal(err) }
	defer windows.CloseHandle(original.handle)
	ro, err := openNativeProgramDataFromRoot(original.handle)
	if err != nil { t.Fatal(err) }
	defer ro.CloseHandle()
	rw, err := openNativeProgramDataWithCreateRight(original.handle)
	if err != nil { t.Fatal(err) }
	defer rw.CloseHandle()
	if ro.id != rw.id || !sameNativePath(ro.nativePath, rw.nativePath) {
		t.Fatal("read-only and exact create-right open resolved different ProgramData objects")
	}
	child, err := makeTestDirectoryAtNativeHandle(rw.handle)
	if err != nil { t.Fatalf("root-relative create-right handle denied test-only child: %v", err) }
	defer windows.CloseHandle(child)
	finalPath, err := nativeFinalPath(child)
	if err != nil || !sameNativePath(filepath.Dir(finalPath), rw.nativePath) ||
		!strings.EqualFold(filepath.Base(finalPath), "test-only-create-child") {
		t.Fatalf("test-only child escaped retained ProgramData handle: %q %v", finalPath, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "ProgramData", "test-only-create-child")); err != nil {
		t.Fatalf("disposable child was not created under test root: %v", err)
	}
}

func TestNativeRootRelativeCreateRightFailsClosedForInvalidAndMissingParents(t *testing.T) {
	for _, bad := range []windows.Handle{0, windows.InvalidHandle} {
		value, err := openNativeProgramDataWithCreateRight(bad)
		if value.handle != 0 { _ = value.CloseHandle() }
		if !errors.Is(err, ErrUnattestedSystemParent) {
			t.Fatalf("invalid root handle accepted: %v", err)
		}
	}
	p, err := openNativeSystemDirectory(t.TempDir())
	if err != nil { t.Fatal(err) }
	defer windows.CloseHandle(p.handle)
	value, err := openNativeProgramDataWithCreateRight(p.handle)
	if value.handle != 0 { _ = value.CloseHandle() }
	if !errors.Is(err, ErrUnqualifiedInstallerParentAccess) {
		t.Fatalf("missing ProgramData was implicitly created or adopted: %v", err)
	}
}

func TestNativeRootRelativeCreateRightRejectsReparseProgramData(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "actual")
	if err := os.Mkdir(target, 0700); err != nil { t.Fatal(err) }
	if err := os.Symlink(target, filepath.Join(root, "ProgramData")); err != nil {
		t.Skipf("native Windows reparse creation unavailable: %v", err)
	}
	held, err := openNativeSystemDirectory(root)
	if err != nil { t.Fatal(err) }
	defer windows.CloseHandle(held.handle)
	value, err := openNativeProgramDataWithCreateRight(held.handle)
	if value.handle != 0 { _ = value.CloseHandle() }
	if err == nil {
		t.Fatal("create-right ProgramData handle adopted a reparse leaf")
	}
}

// The real OS test is diagnostic only. It never creates an FI artifact,
// changes ProgramData ACLs, or accepts an ineligible token as consent.
func TestActualOSProgramDataCreateRightPreflightDoesNotMutate(t *testing.T) {
	p, err := inspectNativeSystemProgramData()
	if err != nil { t.Fatal(err) }
	defer p.Close()
	value, err := p.prepareNativeProgramDataBootstrapParent()
	if err != nil {
		if !errors.Is(err, ErrUnqualifiedInstallerParentAccess) &&
			!errors.Is(err, ErrUnattestedSystemParent) {
			t.Fatalf("unclassified actual Windows preflight failure: %v", err)
		}
		t.Logf("actual OS ProgramData create-rights preflight BLOCKED: %v", err)
		return
	}
	if value.id != p.programData.id {
		t.Fatal("create-rights diagnostic did not preserve original ProgramData identity")
	}
	if err := value.CloseHandle(); err != nil { t.Fatal(err) }
}
