// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"errors"
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

const (
	accessSystemSecurity     = 0x01000000
	saclSecurityInformation  = 0x00000008
	tokenAdjustPrivileges    = 0x00000020
	tokenQuery               = 0x00000008
	sePrivilegeEnabled       = 0x00000002
	errorNotAllAssigned      = syscall.Errno(1300)
	seSecurityPrivilegeName  = "SeSecurityPrivilege"
	saclPrivilegeUnavailable = "SACLPrivilegeUnavailable"
	saclDescriptorReadFailed = "SACLDescriptorReadFailed"
)

type luid struct {
	LowPart  uint32
	HighPart int32
}

type luidAndAttributes struct {
	LUID       luid
	Attributes uint32
}

type tokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [1]luidAndAttributes
}

type saclQueryError struct {
	ReasonCode string
	Err        error
}

func (e *saclQueryError) Error() string {
	return e.Err.Error()
}

func (e *saclQueryError) Unwrap() error {
	return e.Err
}

var (
	procGetCurrentProcess        = securityKernel32.NewProc("GetCurrentProcess")
	procOpenProcessToken         = securityAdvapi32.NewProc("OpenProcessToken")
	procLookupPrivilegeValueW    = securityAdvapi32.NewProc("LookupPrivilegeValueW")
	procAdjustTokenPrivileges    = securityAdvapi32.NewProc("AdjustTokenPrivileges")
	seSecurityPrivilegeOnce      sync.Once
	seSecurityPrivilegeEnableErr error
)

// querySACLDescriptor retrieves the system ACL through the already-proven NTFS
// object handle. FI enables SeSecurityPrivilege once for the process if the
// process token contains it, then reopens the same object with
// ACCESS_SYSTEM_SECURITY. No pathname lookup is performed.
func querySACLDescriptor(handle syscall.Handle) ([]byte, error) {
	if err := ensureSeSecurityPrivilege(); err != nil {
		return nil, &saclQueryError{ReasonCode: saclPrivilegeUnavailable, Err: err}
	}

	securityHandle, err := reopenSACLHandle(handle)
	if err != nil {
		return nil, &saclQueryError{ReasonCode: saclDescriptorReadFailed, Err: err}
	}
	defer syscall.CloseHandle(securityHandle)

	raw, err := getSACLDescriptor(securityHandle)
	if err != nil {
		return nil, &saclQueryError{ReasonCode: saclDescriptorReadFailed, Err: err}
	}
	return raw, nil
}

func saclQueryReasonCode(err error) string {
	var queryErr *saclQueryError
	if errors.As(err, &queryErr) && queryErr.ReasonCode != "" {
		return queryErr.ReasonCode
	}
	return saclDescriptorReadFailed
}

func ensureSeSecurityPrivilege() error {
	seSecurityPrivilegeOnce.Do(func() {
		seSecurityPrivilegeEnableErr = enableSeSecurityPrivilege()
	})
	return seSecurityPrivilegeEnableErr
}

// enableSeSecurityPrivilege enables the privilege on the process token and
// intentionally leaves it enabled for the lifetime of the collector process.
// This is done once rather than toggled around each file so concurrent
// collection cannot race process-wide token state.
func enableSeSecurityPrivilege() error {
	process, _, _ := procGetCurrentProcess.Call()

	var token syscall.Handle
	result, _, callErr := procOpenProcessToken.Call(
		process,
		uintptr(tokenAdjustPrivileges|tokenQuery),
		uintptr(unsafe.Pointer(&token)),
	)
	if result == 0 {
		return windowsCallError("OpenProcessToken(SeSecurityPrivilege)", callErr)
	}
	defer syscall.CloseHandle(token)

	name, err := syscall.UTF16PtrFromString(seSecurityPrivilegeName)
	if err != nil {
		return fmt.Errorf("UTF16PtrFromString(%s): %w", seSecurityPrivilegeName, err)
	}

	var privilegeLUID luid
	result, _, callErr = procLookupPrivilegeValueW.Call(
		0,
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&privilegeLUID)),
	)
	if result == 0 {
		return windowsCallError("LookupPrivilegeValueW(SeSecurityPrivilege)", callErr)
	}

	privileges := tokenPrivileges{
		PrivilegeCount: 1,
		Privileges: [1]luidAndAttributes{{
			LUID:       privilegeLUID,
			Attributes: sePrivilegeEnabled,
		}},
	}

	result, _, callErr = procAdjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&privileges)),
		0,
		0,
		0,
	)
	if result == 0 {
		return windowsCallError("AdjustTokenPrivileges(SeSecurityPrivilege)", callErr)
	}
	if errno, ok := callErr.(syscall.Errno); ok && errno == errorNotAllAssigned {
		return fmt.Errorf("SeSecurityPrivilege is not assigned to the process token")
	}
	return nil
}

func reopenSACLHandle(handle syscall.Handle) (syscall.Handle, error) {
	result, _, callErr := procReOpenFile.Call(
		uintptr(handle),
		accessSystemSecurity,
		uintptr(syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE),
		uintptr(syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT),
	)
	securityHandle := syscall.Handle(result)
	if securityHandle == syscall.InvalidHandle {
		return syscall.InvalidHandle, windowsCallError("ReOpenFile(ACCESS_SYSTEM_SECURITY)", callErr)
	}
	return securityHandle, nil
}

func getSACLDescriptor(handle syscall.Handle) ([]byte, error) {
	requested := uintptr(saclSecurityInformation)
	var needed uint32
	result, _, callErr := procGetKernelObjectSecurity.Call(
		uintptr(handle),
		requested,
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
	)
	if result != 0 && needed == 0 {
		return nil, fmt.Errorf("GetKernelObjectSecurity(SACL) returned an empty descriptor")
	}
	if needed == 0 {
		return nil, windowsCallError("GetKernelObjectSecurity(SACL,size)", callErr)
	}
	if needed > maximumSecurityDescriptorBuffer {
		return nil, fmt.Errorf("SACL security descriptor exceeds bounded buffer limit: %d", needed)
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
		return nil, windowsCallError("GetKernelObjectSecurity(SACL)", callErr)
	}
	if needed == 0 || int(needed) > len(buffer) {
		return nil, fmt.Errorf("GetKernelObjectSecurity(SACL) returned invalid length %d", needed)
	}
	return append([]byte(nil), buffer[:needed]...), nil
}
