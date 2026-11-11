// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The NT directory creation disposition is FILE_CREATE, never FILE_OPEN_IF.
// IO_STATUS_BLOCK.Information must report FILE_CREATED (2); an open/reuse,
// overwrite, or ambiguous result is not an acceptable fresh bootstrap.
const nativeDirectoryCreated uint64 = 2

// createProtectedBootstrapChildAt creates one fixed-name directory RELATIVE
// to an already opened, retained native parent handle. No caller-supplied
// object name, absolute pathname, volume alias or path separator reaches the
// native create operation. The owner and protected DACL are supplied in
// OBJECT_ATTRIBUTES.SecurityDescriptor on the atomic FILE_CREATE request.
//
// This function is package-private, creates no installation authorization,
// and MUST NOT be exposed as a standalone elevated helper. An authenticated
// parent/ancestor issuer and write-ahead installation journal are separate
// requirements before a future installer may use this component.
func createProtectedBootstrapChildAt(parent windows.Handle, descriptor *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	if parent == 0 || parent == windows.InvalidHandle ||
		descriptor == nil || !descriptor.IsValid() {
		return 0, fmt.Errorf("%w: native parent and creation descriptor required", ErrBootstrapInDoubt)
	}
	observed, err := journalParentSecurityFromDescriptor(descriptor)
	if err != nil {
		return 0, fmt.Errorf("%w: inspect intended child owner/DACL: %v", ErrBootstrapInDoubt, err)
	}
	if err := ValidateJournalParentSecurity(observed); err != nil {
		return 0, fmt.Errorf("%w: child creation descriptor does not meet privileged policy: %v", ErrBootstrapInDoubt, err)
	}
	name, err := windows.NewNTUnicodeString(nativeBootstrapDirectoryName)
	if err != nil {
		return 0, fmt.Errorf("%w: encode canonical native child name: %v", ErrBootstrapInDoubt, err)
	}
	attributes := &windows.OBJECT_ATTRIBUTES{
		Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName: name,
		Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
		SecurityDescriptor: descriptor,
	}
	var child windows.Handle
	var ioStatus windows.IO_STATUS_BLOCK
	// SYNCHRONIZE is mandatory with FILE_SYNCHRONOUS_IO_NONALERT.
	// The returned handle includes READ_CONTROL for native owner/DACL
	// attestation; no DELETE or WRITE_DAC rights are requested.
	err = windows.NtCreateFile(
		&child,
		windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE|nativeJournalParentAddFile,
		// The original created directory handle also permits FILE_ADD_FILE
		// for a future journal without reopening the child directory path.
		attributes,
		&ioStatus,
		nil,
		windows.FILE_ATTRIBUTE_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		windows.FILE_CREATE,
		windows.FILE_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	runtime.KeepAlive(name)
	runtime.KeepAlive(descriptor)
	if err != nil {
		if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
			return 0, fmt.Errorf("%w: exact fixed child already exists: %v", ErrBootstrapAlreadyExists, err)
		}
		return 0, fmt.Errorf("%w: native parent-relative FILE_CREATE failed: %w", ErrBootstrapInDoubt, err)
	}
	if child == 0 || child == windows.InvalidHandle {
		return 0, fmt.Errorf("%w: native create reported success without a child handle", ErrBootstrapInDoubt)
	}
	if ioStatus.Information != uintptr(nativeDirectoryCreated) {
		_ = windows.CloseHandle(child)
		return 0, fmt.Errorf("%w: native directory create returned non-created disposition %d", ErrBootstrapInDoubt, ioStatus.Information)
	}
	return child, nil
}
