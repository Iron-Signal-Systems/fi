// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// openNativeProgramDataFromRoot opens exactly the fixed ProgramData directory
// leaf RELATIVE to an already retained native system-volume root HANDLE.
// FILE_OPEN cannot create or repair an object, and the requested access
// permits only read-only identity/descriptor inspection. No absolute path,
// environment variable, device alias or caller-provided child name is used.
//
// The caller still must separately establish that the retained root was
// correctly obtained from Windows and that its owner/DACL and identity are
// trusted. This is not privileged installer authority, and nothing in the
// FI installer or service calls it.
func openNativeProgramDataFromRoot(root windows.Handle) (nativeSystemDirectory, error) {
	if root == 0 || root == windows.InvalidHandle {
		return nativeSystemDirectory{}, fmt.Errorf("%w: missing retained native system-volume root", ErrUnattestedSystemParent)
	}
	if err := requireNativeHandleType(root, true); err != nil {
		return nativeSystemDirectory{}, fmt.Errorf("%w: invalid retained system-volume root: %v", ErrUnattestedSystemParent, err)
	}
	name, err := windows.NewNTUnicodeString("ProgramData")
	if err != nil {
		return nativeSystemDirectory{}, fmt.Errorf("%w: invalid fixed native ProgramData name: %v", ErrUnattestedSystemParent, err)
	}
	attributes := &windows.OBJECT_ATTRIBUTES{
		Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: root,
		ObjectName: name,
		Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	var child windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&child,
		windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
		attributes,
		&iosb,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		windows.FILE_OPEN, // Open existing only. Never FILE_CREATE or FILE_OPEN_IF.
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0, 0,
	)
	runtime.KeepAlive(name)
	if err != nil {
		return nativeSystemDirectory{}, fmt.Errorf("%w: root-relative read-only ProgramData open: %v", ErrUnattestedSystemParent, err)
	}
	if child == 0 || child == windows.InvalidHandle {
		return nativeSystemDirectory{}, fmt.Errorf("%w: NtCreateFile FILE_OPEN returned no handle", ErrUnattestedSystemParent)
	}
	ok := false
	defer func() { if !ok { _ = windows.CloseHandle(child) } }()
	if err := requireNativeHandleType(child, true); err != nil {
		return nativeSystemDirectory{}, fmt.Errorf("%w: root-relative ProgramData is not a plain directory: %v", ErrUnattestedSystemParent, err)
	}
	native, err := nativeFinalPath(child)
	if err != nil || native == "" {
		return nativeSystemDirectory{}, fmt.Errorf("%w: cannot resolve opened ProgramData object: %v", ErrUnattestedSystemParent, err)
	}
	id, err := systemDirectoryIDFromHandle(child)
	if err != nil {
		return nativeSystemDirectory{}, fmt.Errorf("%w: root-relative ProgramData has no full-width NTFS identity: %v", ErrUnattestedSystemParent, err)
	}
	parentPath, err := nativeFinalPath(root)
	if err != nil ||
		!sameNativePath(filepath.Dir(native), parentPath) ||
		!strings.EqualFold(filepath.Base(native), "ProgramData") {
		return nativeSystemDirectory{}, fmt.Errorf("%w: child is not fixed direct ProgramData child of retained root: %v", ErrUnattestedSystemParent, err)
	}
	ok = true
	return nativeSystemDirectory{nativePath: native, id: id, handle: child}, nil
}

// verifyRootRelativeProgramData reads a second independent Windows namespace
// view: the fixed ProgramData leaf via NtCreateFile rooted at the retained
// native system-volume root object. It must refer to EXACTLY the same native
// object that the OS known-folder observer retained earlier, including the
// full 64-bit volume serial and 128-bit NTFS file ID.
//
// Both original handles are revalidated around this check. It is a bounded
// detection mechanism, not an atomic anti-rename guarantee or a cryptographic
// assertion that the host's root/OS APIs are uncompromised.
func (p *nativeSystemParentInspection) verifyRootRelativeProgramData() error {
	if p == nil || p.closed {
		return ErrUnattestedSystemParent
	}
	if err := p.verifyRetained(); err != nil {
		return fmt.Errorf("%w: before root-relative ProgramData inspection: %v", ErrUnattestedSystemParent, err)
	}
	relative, err := openNativeProgramDataFromRoot(p.root.handle)
	if err != nil {
		return err
	}
	defer relative.CloseHandle()
	if relative.id != p.programData.id ||
		!sameNativePath(relative.nativePath, p.programData.nativePath) {
		return fmt.Errorf("%w: root-relative ProgramData is not the original OS known-folder object", ErrUnattestedSystemParent)
	}
	if err := p.verifyRetained(); err != nil {
		return fmt.Errorf("%w: after root-relative ProgramData inspection: %v", ErrUnattestedSystemParent, err)
	}
	return nil
}

// closeNativeSystemDirectoryHandle is intentionally handle-only: the
// original path and any FI-created filesystem evidence are never removed.
func (d *nativeSystemDirectory) CloseHandle() error {
	if d == nil || d.handle == 0 || d.handle == windows.InvalidHandle {
		return nil
	}
	err := windows.CloseHandle(d.handle)
	d.handle = 0
	return err
}

