// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	readControl = 0x00020000

	ownerSecurityInformation = 0x00000001
	groupSecurityInformation = 0x00000002
	daclSecurityInformation  = 0x00000004

	maximumSecurityDescriptorBuffer = 128 * 1024
)

var (
	securityKernel32            = syscall.NewLazyDLL("kernel32.dll")
	securityAdvapi32            = syscall.NewLazyDLL("advapi32.dll")
	procReOpenFile              = securityKernel32.NewProc("ReOpenFile")
	procGetKernelObjectSecurity = securityAdvapi32.NewProc("GetKernelObjectSecurity")
)

// querySecurityDescriptor reopens the already-proven NTFS object handle with
// READ_CONTROL and retrieves owner, primary-group, and DACL state as one exact
// self-relative security descriptor. No pathname lookup is performed here.
func querySecurityDescriptor(handle syscall.Handle) ([]byte, error) {
	securityHandle, err := reopenSecurityHandle(handle)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(securityHandle)

	requested := uintptr(ownerSecurityInformation | groupSecurityInformation | daclSecurityInformation)
	var needed uint32
	result, _, callErr := procGetKernelObjectSecurity.Call(
		uintptr(securityHandle),
		requested,
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
	)
	if result != 0 && needed == 0 {
		return nil, fmt.Errorf("GetKernelObjectSecurity returned an empty descriptor")
	}
	if needed == 0 {
		return nil, windowsCallError("GetKernelObjectSecurity(size)", callErr)
	}
	if needed > maximumSecurityDescriptorBuffer {
		return nil, fmt.Errorf("security descriptor exceeds bounded buffer limit: %d", needed)
	}

	buffer := make([]byte, needed)
	result, _, callErr = procGetKernelObjectSecurity.Call(
		uintptr(securityHandle),
		requested,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&needed)),
	)
	if result == 0 {
		return nil, windowsCallError("GetKernelObjectSecurity", callErr)
	}
	if needed == 0 || int(needed) > len(buffer) {
		return nil, fmt.Errorf("GetKernelObjectSecurity returned invalid length %d", needed)
	}
	return append([]byte(nil), buffer[:needed]...), nil
}

func reopenSecurityHandle(handle syscall.Handle) (syscall.Handle, error) {
	result, _, callErr := procReOpenFile.Call(
		uintptr(handle),
		readControl,
		uintptr(syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE),
		uintptr(syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT),
	)
	securityHandle := syscall.Handle(result)
	if securityHandle == syscall.InvalidHandle {
		return syscall.InvalidHandle, windowsCallError("ReOpenFile(READ_CONTROL)", callErr)
	}
	return securityHandle, nil
}

func windowsCallError(operation string, callErr error) error {
	if callErr != nil && callErr != syscall.Errno(0) {
		return fmt.Errorf("%s: %w", operation, callErr)
	}
	return fmt.Errorf("%s failed", operation)
}
