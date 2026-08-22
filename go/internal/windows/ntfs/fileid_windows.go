// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const fileIDType = 0

var procOpenFileByID = kernel32.NewProc("OpenFileById")

// fileIDDescriptor matches FILE_ID_DESCRIPTOR. The union is represented by its
// largest 16-byte member so the structure remains the documented 24-byte ABI on
// Windows amd64/arm64. FileIdType uses the first 8 bytes as LARGE_INTEGER FileId.
type fileIDDescriptor struct {
	Size       uint32
	Type       uint32
	Identifier [16]byte
}

var (
	_ [24 - unsafe.Sizeof(fileIDDescriptor{})]byte
	_ [unsafe.Sizeof(fileIDDescriptor{}) - 24]byte
)

// composeNTFSFileID reconstructs the 64-bit NTFS file reference used by
// OpenFileById from FI's separate record-number and sequence-number fields.
func composeNTFSFileID(identity records.NTFSObjectIdentity) (uint64, error) {
	if identity.MethodVersion != IdentityMethodVersion {
		return 0, ErrUnsupportedIdentityMethod
	}
	if err := records.ValidateNTFSObjectIdentity(identity); err != nil {
		return 0, err
	}

	recordNumber, err := strconv.ParseUint(identity.FileReferenceNumber, 10, 48)
	if err != nil {
		return 0, fmt.Errorf("file reference number: %w", err)
	}
	sequenceNumber, err := strconv.ParseUint(identity.SequenceNumber, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("sequence number: %w", err)
	}
	return recordNumber | sequenceNumber<<48, nil
}

// openFileByObjectIdentity opens an NTFS object by the exact FI object identity
// using the already-open governed-root handle as OpenFileById's volume hint.
//
// OpenFileById is still read-only here: FI requests FILE_READ_ATTRIBUTES only.
// Share flags allow normal workloads to continue modifying/renaming/deleting the
// object while FI observes it; they do not grant FI write/delete access.
func openFileByObjectIdentity(volumeHint syscall.Handle, identity records.NTFSObjectIdentity) (syscall.Handle, error) {
	fileID, err := composeNTFSFileID(identity)
	if err != nil {
		return syscall.InvalidHandle, err
	}

	descriptor := fileIDDescriptor{
		Size: uint32(unsafe.Sizeof(fileIDDescriptor{})),
		Type: fileIDType,
	}
	binary.LittleEndian.PutUint64(descriptor.Identifier[:8], fileID)

	r1, _, callErr := procOpenFileByID.Call(
		uintptr(volumeHint),
		uintptr(unsafe.Pointer(&descriptor)),
		fileReadAttributes,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		0,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
	)
	runtime.KeepAlive(&descriptor)

	handle := syscall.Handle(r1)
	if handle == syscall.InvalidHandle {
		return syscall.InvalidHandle, callErr
	}
	return handle, nil
}
