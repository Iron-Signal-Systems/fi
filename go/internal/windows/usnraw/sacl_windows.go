// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnraw

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	saclAccessSystemSecurity       = 0x01000000
	saclSecurityInformation        = 0x00000008
	saclMaximumDescriptorBytes     = 128 * 1024
	saclTokenAdjustPrivileges      = 0x00000020
	saclTokenQuery                 = 0x00000008
	saclPrivilegeEnabled           = 0x00000002
	saclWindowsErrorNotAllAssigned = syscall.Errno(1300)
)

type saclLUID struct {
	LowPart  uint32
	HighPart int32
}

type saclLUIDAndAttributes struct {
	LUID       saclLUID
	Attributes uint32
}

type saclPrivilegeScope struct {
	Token         syscall.Handle
	Previous      saclTokenPrivileges
	RestoreNeeded bool
}

type saclTokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [1]saclLUIDAndAttributes
}

var (
	saclAdvapi32                    = syscall.NewLazyDLL("advapi32.dll")
	procSACLAdjustTokenPrivileges   = saclAdvapi32.NewProc("AdjustTokenPrivileges")
	procSACLGetKernelObjectSecurity = saclAdvapi32.NewProc("GetKernelObjectSecurity")
	procSACLGetCurrentProcess       = kernel32.NewProc("GetCurrentProcess")
	procSACLLookupPrivilegeValueW   = saclAdvapi32.NewProc("LookupPrivilegeValueW")
	procSACLOpenProcessToken        = saclAdvapi32.NewProc("OpenProcessToken")
	procSACLSetLastError            = kernel32.NewProc("SetLastError")
)

// ReadSACL returns the raw self-relative SACL security descriptor for one exact
// NTFS object identity inside governedRoot. The privileged package performs only
// mechanical authorization, containment, scoped privilege enablement, and
// descriptor retrieval. It does not parse or interpret the SACL.
func ReadSACL(
	governedRoot string,
	fileReferenceNumber uint64,
	sequenceNumber uint16,
) (data []byte, err error) {
	if fileReferenceNumber >= 1<<48 {
		return nil, errors.New("file reference number exceeds 48-bit NTFS record number")
	}
	if _, err := DriveForRoot(governedRoot); err != nil {
		return nil, err
	}

	rootHandle, err := containmentOpenPath(governedRoot)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(rootHandle)

	rootPath, err := containmentFinalVolumePath(rootHandle)
	if err != nil {
		return nil, err
	}

	privilegeScope, err := enableSACLPrivilege()
	if err != nil {
		return nil, err
	}
	defer func() {
		restoreErr := restoreSACLPrivilege(privilegeScope)
		if restoreErr != nil {
			data = nil
			err = errors.Join(err, restoreErr)
		}
	}()

	targetHandle, err := containmentOpenFileByIDAccess(
		rootHandle,
		fileReferenceNumber,
		sequenceNumber,
		saclAccessSystemSecurity,
	)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(targetHandle)

	targetPath, err := containmentFinalVolumePath(targetHandle)
	if err != nil {
		return nil, err
	}
	if !containmentPathContainedBy(rootPath, targetPath) {
		return nil, syscall.ERROR_ACCESS_DENIED
	}

	return readSACLDescriptor(targetHandle)
}

func enableSACLPrivilege() (saclPrivilegeScope, error) {
	process, _, _ := procSACLGetCurrentProcess.Call()

	var token syscall.Handle
	result, _, callErr := procSACLOpenProcessToken.Call(
		process,
		uintptr(saclTokenAdjustPrivileges|saclTokenQuery),
		uintptr(unsafe.Pointer(&token)),
	)
	if result == 0 {
		return saclPrivilegeScope{}, fmt.Errorf(
			"open process token for SeSecurityPrivilege: %w",
			saclNormalizeCallError(callErr),
		)
	}

	closeOnError := true
	defer func() {
		if closeOnError {
			_ = syscall.CloseHandle(token)
		}
	}()

	name, err := syscall.UTF16PtrFromString("SeSecurityPrivilege")
	if err != nil {
		return saclPrivilegeScope{}, fmt.Errorf("UTF16PtrFromString(SeSecurityPrivilege): %w", err)
	}

	var privilegeLUID saclLUID
	result, _, callErr = procSACLLookupPrivilegeValueW.Call(
		0,
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&privilegeLUID)),
	)
	if result == 0 {
		return saclPrivilegeScope{}, fmt.Errorf(
			"lookup SeSecurityPrivilege: %w",
			saclNormalizeCallError(callErr),
		)
	}

	newState := saclTokenPrivileges{
		PrivilegeCount: 1,
		Privileges: [1]saclLUIDAndAttributes{{
			LUID:       privilegeLUID,
			Attributes: saclPrivilegeEnabled,
		}},
	}

	var previous saclTokenPrivileges
	var previousLength uint32

	_, _, _ = procSACLSetLastError.Call(0)

	result, _, callErr = procSACLAdjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&newState)),
		unsafe.Sizeof(previous),
		uintptr(unsafe.Pointer(&previous)),
		uintptr(unsafe.Pointer(&previousLength)),
	)
	runtime.KeepAlive(&newState)
	if result == 0 {
		return saclPrivilegeScope{}, fmt.Errorf(
			"enable SeSecurityPrivilege: %w",
			saclNormalizeCallError(callErr),
		)
	}

	switch code := saclWindowsErrorCode(callErr); code {
	case 0:
		closeOnError = false
		return saclPrivilegeScope{
			Token:         token,
			Previous:      previous,
			RestoreNeeded: previous.PrivilegeCount > 0,
		}, nil
	case uint32(saclWindowsErrorNotAllAssigned):
		return saclPrivilegeScope{}, fmt.Errorf(
			"SeSecurityPrivilege is not assigned to the process token: %w",
			saclWindowsErrorNotAllAssigned,
		)
	default:
		return saclPrivilegeScope{}, fmt.Errorf(
			"enable SeSecurityPrivilege returned Windows error %d: %w",
			code,
			saclNormalizeCallError(callErr),
		)
	}
}

func readSACLDescriptor(handle syscall.Handle) ([]byte, error) {
	requested := uintptr(saclSecurityInformation)
	var needed uint32
	result, _, callErr := procSACLGetKernelObjectSecurity.Call(
		uintptr(handle),
		requested,
		0,
		0,
		uintptr(unsafe.Pointer(&needed)),
	)
	if result != 0 && needed == 0 {
		return nil, errors.New("GetKernelObjectSecurity(SACL) returned an empty descriptor")
	}
	if needed == 0 {
		return nil, saclWindowsCallError("GetKernelObjectSecurity(SACL,size)", callErr)
	}
	if needed > saclMaximumDescriptorBytes {
		return nil, fmt.Errorf("SACL security descriptor exceeds bounded buffer limit: %d", needed)
	}

	buffer := make([]byte, needed)
	result, _, callErr = procSACLGetKernelObjectSecurity.Call(
		uintptr(handle),
		requested,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&needed)),
	)
	if result == 0 {
		return nil, saclWindowsCallError("GetKernelObjectSecurity(SACL)", callErr)
	}
	if needed == 0 || int(needed) > len(buffer) {
		return nil, fmt.Errorf("GetKernelObjectSecurity(SACL) returned invalid length %d", needed)
	}
	return append([]byte(nil), buffer[:needed]...), nil
}

func restoreSACLPrivilege(scope saclPrivilegeScope) error {
	if scope.Token == 0 || scope.Token == syscall.InvalidHandle {
		return errors.New("restore SeSecurityPrivilege: process token handle is invalid")
	}

	var restoreErr error
	if scope.RestoreNeeded {
		_, _, _ = procSACLSetLastError.Call(0)

		result, _, callErr := procSACLAdjustTokenPrivileges.Call(
			uintptr(scope.Token),
			0,
			uintptr(unsafe.Pointer(&scope.Previous)),
			0,
			0,
			0,
		)
		switch {
		case result == 0:
			restoreErr = fmt.Errorf(
				"restore SeSecurityPrivilege: %w",
				saclNormalizeCallError(callErr),
			)
		case saclWindowsErrorCode(callErr) != 0:
			restoreErr = fmt.Errorf(
				"restore SeSecurityPrivilege returned Windows error %d: %w",
				saclWindowsErrorCode(callErr),
				saclNormalizeCallError(callErr),
			)
		}
	}

	closeErr := syscall.CloseHandle(scope.Token)
	if closeErr != nil {
		closeErr = fmt.Errorf("close SeSecurityPrivilege process token: %w", closeErr)
	}
	return errors.Join(restoreErr, closeErr)
}

func saclNormalizeCallError(err error) error {
	if err == nil {
		return errors.New("Windows call failed without an error code")
	}
	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return errors.New("Windows call failed without an error code")
	}
	return err
}

func saclWindowsCallError(operation string, callErr error) error {
	if callErr != nil && callErr != syscall.Errno(0) {
		return fmt.Errorf("%s: %w", operation, callErr)
	}
	return fmt.Errorf("%s failed", operation)
}

func saclWindowsErrorCode(err error) uint32 {
	if err == nil {
		return 0
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return uint32(errno)
	}
	return 0
}
