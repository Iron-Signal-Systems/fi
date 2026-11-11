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

// A directory parent handle needs FILE_ADD_FILE (0x2) to create a regular
// file below it. This is distinct from FILE_ADD_SUBDIRECTORY (0x4).
const nativeJournalParentAddFile uint32 = 0x00000002

// createNativeJournalFileAt atomically creates exactly the fixed FI v2
// journal name under the *retained directory object* provided by the caller.
// NtCreateFile's RootDirectory prevents a second path-based parent lookup.
//
// The caller must already attest the held parent owner/DACL, native identity
// and host/transaction provenance. This primitive neither proves installer
// authorization nor deletes or retries an uncertain creation. The caller
// retains the returned handle for all journal writes, then closes it without
// deleting the file, including on failure.
func createNativeJournalFileAt(parent windows.Handle) (windows.Handle, error) {
	if parent == 0 || parent == windows.InvalidHandle {
		return 0, fmt.Errorf("%w: no live journal parent handle", ErrCreationInDoubt)
	}
	if err := requireNativeHandleType(parent, true); err != nil {
		return 0, fmt.Errorf("%w: retained journal parent is invalid: %v", ErrCreationInDoubt, err)
	}
	name, err := windows.NewNTUnicodeString(nativeCreationJournalName)
	if err != nil {
		return 0, fmt.Errorf("%w: encode fixed journal file name: %v", ErrCreationInDoubt, err)
	}
	attributes := &windows.OBJECT_ATTRIBUTES{
		Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName: name,
		Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	var child windows.Handle
	var ioStatus windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&child,
		windows.GENERIC_READ | windows.GENERIC_WRITE | windows.SYNCHRONIZE,
		attributes,
		&ioStatus,
		nil,
		windows.FILE_ATTRIBUTE_NORMAL,
		0, // Exclusively owned: do not permit other readers/writers/deleters.
		windows.FILE_CREATE, // Fail on any preexisting file or reparse point.
		windows.FILE_NON_DIRECTORY_FILE |
			windows.FILE_SYNCHRONOUS_IO_NONALERT |
			windows.FILE_WRITE_THROUGH,
		0,
		0,
	)
	runtime.KeepAlive(name)
	if err != nil {
		if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
			return 0, fmt.Errorf("%w: fixed creation journal already exists: %v", ErrCreationInDoubt, err)
		}
		return 0, fmt.Errorf("%w: parent-relative journal FILE_CREATE: %v", ErrCreationInDoubt, err)
	}
	if child == 0 || child == windows.InvalidHandle {
		return 0, fmt.Errorf("%w: NtCreateFile returned no journal handle", ErrCreationInDoubt)
	}
	if ioStatus.Information != uintptr(nativeDirectoryCreated) {
		_ = windows.CloseHandle(child)
		return 0, fmt.Errorf("%w: journal creation disposition was not FILE_CREATED (%d)", ErrCreationInDoubt, ioStatus.Information)
	}
	return child, nil
}
