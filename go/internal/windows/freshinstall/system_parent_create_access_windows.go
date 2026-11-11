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

// openNativeProgramDataWithCreateRight opens only the fixed ProgramData child
// of a retained root HANDLE. FILE_OPEN is nonmutating. The access mask adds
// precisely FILE_ADD_SUBDIRECTORY for a future private bootstrap operation.
// This is NOT installer consent, a trusted issuer or installation authority.
func openNativeProgramDataWithCreateRight(root windows.Handle) (nativeSystemDirectory, error) {
	if root == 0 || root == windows.InvalidHandle {
		return nativeSystemDirectory{}, ErrUnattestedSystemParent
	}
	if err := requireNativeHandleType(root, true); err != nil {
		return nativeSystemDirectory{}, fmt.Errorf("%w: invalid retained root: %v", ErrUnattestedSystemParent, err)
	}
	name, err := windows.NewNTUnicodeString("ProgramData")
	if err != nil {
		return nativeSystemDirectory{}, fmt.Errorf("%w: fixed leaf encoding: %v", ErrUnattestedSystemParent, err)
	}
	oa := &windows.OBJECT_ATTRIBUTES{
		Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: root,
		ObjectName: name,
		Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	var handle windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE|installerParentCreateChild,
		oa, &iosb, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0, 0,
	)
	runtime.KeepAlive(name)
	if err != nil {
		return nativeSystemDirectory{}, fmt.Errorf("%w: root-relative ProgramData FILE_OPEN with FILE_ADD_SUBDIRECTORY: %v", ErrUnqualifiedInstallerParentAccess, err)
	}
	if handle == 0 || handle == windows.InvalidHandle {
		return nativeSystemDirectory{}, fmt.Errorf("%w: no native ProgramData handle", ErrUnattestedSystemParent)
	}
	ok := false
	defer func() { if !ok { _ = windows.CloseHandle(handle) } }()
	if err := requireNativeHandleType(handle, true); err != nil {
		return nativeSystemDirectory{}, fmt.Errorf("%w: invalid ProgramData type/reparse: %v", ErrUnattestedSystemParent, err)
	}
	path, err := nativeFinalPath(handle)
	if err != nil || path == "" {
		return nativeSystemDirectory{}, fmt.Errorf("%w: unresolved native ProgramData: %v", ErrUnattestedSystemParent, err)
	}
	rootPath, err := nativeFinalPath(root)
	if err != nil || !sameNativePath(filepath.Dir(path), rootPath) ||
		!strings.EqualFold(filepath.Base(path), "ProgramData") {
		return nativeSystemDirectory{}, fmt.Errorf("%w: ProgramData not a direct child of retained root: %v", ErrUnattestedSystemParent, err)
	}
	id, err := systemDirectoryIDFromHandle(handle)
	if err != nil {
		return nativeSystemDirectory{}, err
	}
	ok = true
	return nativeSystemDirectory{nativePath: path, id: id, handle: handle}, nil
}

// prepareNativeProgramDataBootstrapParent is a READ-ONLY preflight: it checks
// actual elevated process rights and the original ProgramData ACL, then opens
// a handle with the exact future create right relative to the retained root.
// It does NOT call createProtectedBootstrapChildAt or grant permission to do so.
// No caller may treat a successful observation as authenticated human consent.
func (p *nativeSystemParentInspection) prepareNativeProgramDataBootstrapParent() (nativeSystemDirectory, error) {
	if p == nil || p.closed {
		return nativeSystemDirectory{}, ErrUnattestedSystemParent
	}
	if err := p.verifyRootRelativeProgramData(); err != nil {
		return nativeSystemDirectory{}, err
	}
	rights, err := p.inspectInstallerProgramDataAccess()
	if err != nil {
		return nativeSystemDirectory{}, fmt.Errorf("%w: native effective access: %v", ErrUnqualifiedInstallerParentAccess, err)
	}
	if err := AssessInstallerParentAccess(rights); err != nil {
		return nativeSystemDirectory{}, err
	}
	// Keep the independently observed original descriptor, not an
	// unauthenticated descriptor supplied by the new handle or caller.
	before, err := windows.GetSecurityInfo(p.programData.handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || before == nil || !before.IsValid() {
		return nativeSystemDirectory{}, fmt.Errorf("%w: original owner/DACL unavailable: %v", ErrUnattestedSystemParent, err)
	}
	prepared, err := openNativeProgramDataWithCreateRight(p.root.handle)
	if err != nil {
		return nativeSystemDirectory{}, err
	}
	accepted := false
	defer func() { if !accepted { _ = prepared.CloseHandle() } }()
	if prepared.id != p.programData.id || !sameNativePath(prepared.nativePath, p.programData.nativePath) {
		return nativeSystemDirectory{}, fmt.Errorf("%w: create-right handle is not original OS ProgramData", ErrUnattestedSystemParent)
	}
	after, err := windows.GetSecurityInfo(prepared.handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil || after == nil || !after.IsValid() || after.String() != before.String() {
		return nativeSystemDirectory{}, fmt.Errorf("%w: ProgramData ACL changed before create-right handoff: %v", ErrUnattestedSystemParent, err)
	}
	if err := p.verifyRetained(); err != nil {
		return nativeSystemDirectory{}, err
	}
	accepted = true
	return prepared, nil
}
