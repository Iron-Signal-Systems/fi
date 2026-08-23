// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"syscall"
	"testing"
	"unsafe"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestDirectorySecurityOpenByObjectIdentity(t *testing.T) {
	path := t.TempDir()

	units, err := syscall.UTF16FromString(path)
	if err != nil {
		t.Fatal(err)
	}

	handle, err := openPath(units)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)

	state, err := queryNativeState(handle)
	if err != nil {
		t.Fatal(err)
	}

	_, identity, err := buildObjectIdentity(
		state.ID.VolumeSerialNumber,
		state.ID.FileID,
	)
	if err != nil {
		t.Fatal(err)
	}

	reopened, reopenErr := reopenSecurityHandle(handle)
	switch {
	case reopenErr != nil:
		t.Logf("ReOpenFile(READ_CONTROL) directory result: %v", reopenErr)

	default:
		t.Log("ReOpenFile(READ_CONTROL) directory result: success")
		syscall.CloseHandle(reopened)
	}

	securityHandle, err := openFileByObjectIdentityAccessForTest(
		handle,
		identity,
		readControl,
	)
	if err != nil {
		t.Fatalf("OpenFileById(READ_CONTROL): %v", err)
	}
	defer syscall.CloseHandle(securityHandle)

	raw, err := getSecurityDescriptorFromGrantedHandleForTest(securityHandle)
	if err != nil {
		t.Fatal(err)
	}

	observation, err := records.ParseSecurityDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := records.ValidateSecurityObservation(observation); err != nil {
		t.Fatal(err)
	}

	if observation.OwnerSID == "" {
		t.Fatal("expected owner SID")
	}
	if observation.DACL.State == "" {
		t.Fatal("expected DACL state")
	}
}

func TestDirectorySACLOpenByObjectIdentity(t *testing.T) {
	if err := ensureSeSecurityPrivilege(); err != nil {
		t.Skipf("SeSecurityPrivilege unavailable: %v", err)
	}

	path := t.TempDir()

	units, err := syscall.UTF16FromString(path)
	if err != nil {
		t.Fatal(err)
	}

	handle, err := openPath(units)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)

	state, err := queryNativeState(handle)
	if err != nil {
		t.Fatal(err)
	}

	_, identity, err := buildObjectIdentity(
		state.ID.VolumeSerialNumber,
		state.ID.FileID,
	)
	if err != nil {
		t.Fatal(err)
	}

	reopened, reopenErr := reopenSACLHandle(handle)
	switch {
	case reopenErr != nil:
		t.Logf("ReOpenFile(ACCESS_SYSTEM_SECURITY) directory result: %v", reopenErr)

	default:
		t.Log("ReOpenFile(ACCESS_SYSTEM_SECURITY) directory result: success")
		syscall.CloseHandle(reopened)
	}

	securityHandle, err := openFileByObjectIdentityAccessForTest(
		handle,
		identity,
		accessSystemSecurity,
	)
	if err != nil {
		t.Fatalf("OpenFileById(ACCESS_SYSTEM_SECURITY): %v", err)
	}
	defer syscall.CloseHandle(securityHandle)

	raw, err := getSACLDescriptor(securityHandle)
	if err != nil {
		t.Fatal(err)
	}

	observation, err := records.ParseSACLDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := records.ValidateSACLObservation(observation); err != nil {
		t.Fatal(err)
	}
}

func openFileByObjectIdentityAccessForTest(
	volumeHint syscall.Handle,
	identity records.NTFSObjectIdentity,
	desiredAccess uint32,
) (syscall.Handle, error) {
	fileID, err := composeNTFSFileID(identity)
	if err != nil {
		return syscall.InvalidHandle, err
	}

	descriptor := fileIDDescriptor{
		Size: uint32(unsafe.Sizeof(fileIDDescriptor{})),
		Type: fileIDType,
	}
	binary.LittleEndian.PutUint64(descriptor.Identifier[:8], fileID)

	result, _, callErr := procOpenFileByID.Call(
		uintptr(volumeHint),
		uintptr(unsafe.Pointer(&descriptor)),
		uintptr(desiredAccess),
		uintptr(syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE),
		0,
		uintptr(syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT),
	)
	runtime.KeepAlive(&descriptor)

	handle := syscall.Handle(result)
	if handle == syscall.InvalidHandle {
		return syscall.InvalidHandle, windowsCallError(
			"OpenFileById(directory-security-test)",
			callErr,
		)
	}

	return handle, nil
}

func getSecurityDescriptorFromGrantedHandleForTest(
	handle syscall.Handle,
) ([]byte, error) {
	requested := uintptr(
		ownerSecurityInformation |
			groupSecurityInformation |
			daclSecurityInformation,
	)

	var needed uint32

	result, _, callErr := procGetKernelObjectSecurity.Call(
		uintptr(handle),
		requested,
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
	)

	if result != 0 && needed == 0 {
		return nil, fmt.Errorf(
			"GetKernelObjectSecurity returned an empty descriptor",
		)
	}
	if needed == 0 {
		return nil, windowsCallError(
			"GetKernelObjectSecurity(directory,size)",
			callErr,
		)
	}
	if needed > maximumSecurityDescriptorBuffer {
		return nil, fmt.Errorf(
			"security descriptor exceeds bounded buffer limit: %d",
			needed,
		)
	}

	buffer := make([]byte, needed)

	result, _, callErr = procGetKernelObjectSecurity.Call(
		uintptr(handle),
		requested,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&needed)),
	)
	if result == 0 {
		return nil, windowsCallError(
			"GetKernelObjectSecurity(directory)",
			callErr,
		)
	}
	if needed == 0 || int(needed) > len(buffer) {
		return nil, fmt.Errorf(
			"GetKernelObjectSecurity returned invalid length %d",
			needed,
		)
	}

	return append([]byte(nil), buffer[:needed]...), nil
}
