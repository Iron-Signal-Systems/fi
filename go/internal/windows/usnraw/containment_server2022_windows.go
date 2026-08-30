// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnraw

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"
)

const (
	containmentServer2022Major = 10
	containmentServer2022Minor = 0
	containmentServer2022Build = 20348

	containmentTokenQuery            = 0x0008
	containmentTokenAdjustPrivileges = 0x0020
	containmentSEPrivilegeEnabled    = 0x00000002
	containmentErrorNotAllAssigned   = 1300
)

type containmentLUID struct {
	LowPart  uint32
	HighPart int32
}

type containmentLUIDAndAttributes struct {
	LUID       containmentLUID
	Attributes uint32
}

type containmentOSVersionInfo struct {
	Size             uint32
	MajorVersion     uint32
	MinorVersion     uint32
	BuildNumber      uint32
	PlatformID       uint32
	CSDVersion       [128]uint16
	ServicePackMajor uint16
	ServicePackMinor uint16
	SuiteMask        uint16
	ProductType      byte
	Reserved         byte
}

type containmentPrivilegeScope struct {
	Token         syscall.Handle
	Previous      containmentTokenPrivileges
	RestoreNeeded bool
}

type containmentTokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [1]containmentLUIDAndAttributes
}

var (
	containmentAdvapi32                  = syscall.NewLazyDLL("advapi32.dll")
	containmentNTDLL                     = syscall.NewLazyDLL("ntdll.dll")
	procContainmentAdjustTokenPrivileges = containmentAdvapi32.NewProc("AdjustTokenPrivileges")
	procContainmentGetCurrentProcess     = kernel32.NewProc("GetCurrentProcess")
	procContainmentLookupPrivilegeValueW = containmentAdvapi32.NewProc("LookupPrivilegeValueW")
	procContainmentOpenProcessToken      = containmentAdvapi32.NewProc("OpenProcessToken")
	procContainmentRtlGetVersion         = containmentNTDLL.NewProc("RtlGetVersion")
	procContainmentSetLastError          = kernel32.NewProc("SetLastError")
)

// containmentCheckServer2022 is the Windows Server 2022-only fallback for
// protected system objects that return ERROR_ACCESS_DENIED from the normal
// zero-access OpenFileById containment call.
//
// The fallback temporarily enables SeBackupPrivilege, retries the exact same
// zero-access OpenFileById once, resolves only mechanical governed-root
// containment, and restores the exact previous privilege state before returning.
func containmentCheckServer2022(
	rootHandle syscall.Handle,
	rootPath string,
	fileReferenceNumber uint64,
	sequenceNumber uint16,
) (result ContainmentResult, err error) {
	scope, err := containmentEnableBackupPrivilegeServer2022()
	if err != nil {
		return 0, err
	}
	defer func() {
		restoreErr := containmentRestoreBackupPrivilegeServer2022(scope)
		if restoreErr != nil {
			result = 0
			err = errors.Join(err, restoreErr)
		}
	}()

	targetHandle, err := containmentOpenFileByID(
		rootHandle,
		fileReferenceNumber,
		sequenceNumber,
	)
	if err != nil {
		switch {
		case errors.Is(err, syscall.ERROR_FILE_NOT_FOUND),
			errors.Is(err, syscall.ERROR_PATH_NOT_FOUND),
			errors.Is(err, containmentWindowsErrorInvalidParameter):
			return ContainmentUnavailable, nil
		default:
			return 0, err
		}
	}
	defer syscall.CloseHandle(targetHandle)

	targetPath, err := containmentFinalVolumePath(targetHandle)
	if err != nil {
		return 0, err
	}
	if containmentPathContainedBy(rootPath, targetPath) {
		return ContainmentContained, nil
	}
	return ContainmentOutside, nil
}

func containmentEnableBackupPrivilegeServer2022() (containmentPrivilegeScope, error) {
	process, _, _ := procContainmentGetCurrentProcess.Call()

	var token syscall.Handle
	r1, _, callErr := procContainmentOpenProcessToken.Call(
		process,
		uintptr(containmentTokenQuery|containmentTokenAdjustPrivileges),
		uintptr(unsafe.Pointer(&token)),
	)
	if r1 == 0 {
		return containmentPrivilegeScope{},
			fmt.Errorf(
				"open process token for SeBackupPrivilege: %w",
				containmentNormalizeCallErrorServer2022(callErr),
			)
	}

	closeOnError := true
	defer func() {
		if closeOnError {
			_ = syscall.CloseHandle(token)
		}
	}()

	name, err := syscall.UTF16PtrFromString("SeBackupPrivilege")
	if err != nil {
		return containmentPrivilegeScope{}, err
	}

	var privilegeLUID containmentLUID
	r1, _, callErr = procContainmentLookupPrivilegeValueW.Call(
		0,
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&privilegeLUID)),
	)
	if r1 == 0 {
		return containmentPrivilegeScope{},
			fmt.Errorf(
				"lookup SeBackupPrivilege: %w",
				containmentNormalizeCallErrorServer2022(callErr),
			)
	}

	newState := containmentTokenPrivileges{
		PrivilegeCount: 1,
	}
	newState.Privileges[0] = containmentLUIDAndAttributes{
		LUID:       privilegeLUID,
		Attributes: containmentSEPrivilegeEnabled,
	}

	var previous containmentTokenPrivileges
	var previousLength uint32

	_, _, _ = procContainmentSetLastError.Call(0)

	r1, _, callErr = procContainmentAdjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&newState)),
		unsafe.Sizeof(previous),
		uintptr(unsafe.Pointer(&previous)),
		uintptr(unsafe.Pointer(&previousLength)),
	)
	if r1 == 0 {
		return containmentPrivilegeScope{},
			fmt.Errorf(
				"enable SeBackupPrivilege: %w",
				containmentNormalizeCallErrorServer2022(callErr),
			)
	}

	switch code := containmentWindowsErrorCodeServer2022(callErr); code {
	case 0:
		closeOnError = false
		return containmentPrivilegeScope{
			Token:         token,
			Previous:      previous,
			RestoreNeeded: previous.PrivilegeCount > 0,
		}, nil

	case containmentErrorNotAllAssigned:
		return containmentPrivilegeScope{},
			errors.New("SeBackupPrivilege is not present in FIUSNReader service token")

	default:
		return containmentPrivilegeScope{},
			fmt.Errorf(
				"enable SeBackupPrivilege returned Windows error %d: %w",
				code,
				containmentNormalizeCallErrorServer2022(callErr),
			)
	}
}

func containmentIsServer2022Version(major, minor, build uint32) bool {
	return major == containmentServer2022Major &&
		minor == containmentServer2022Minor &&
		build == containmentServer2022Build
}

func containmentNormalizeCallErrorServer2022(err error) error {
	if err == nil {
		return errors.New("Windows call failed without an error code")
	}
	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return errors.New("Windows call failed without an error code")
	}
	return err
}

func containmentRestoreBackupPrivilegeServer2022(scope containmentPrivilegeScope) error {
	if scope.Token == 0 || scope.Token == syscall.InvalidHandle {
		return errors.New("restore SeBackupPrivilege: process token handle is invalid")
	}

	var restoreErr error
	if scope.RestoreNeeded {
		_, _, _ = procContainmentSetLastError.Call(0)

		r1, _, callErr := procContainmentAdjustTokenPrivileges.Call(
			uintptr(scope.Token),
			0,
			uintptr(unsafe.Pointer(&scope.Previous)),
			0,
			0,
			0,
		)
		switch {
		case r1 == 0:
			restoreErr = fmt.Errorf(
				"restore SeBackupPrivilege: %w",
				containmentNormalizeCallErrorServer2022(callErr),
			)

		case containmentWindowsErrorCodeServer2022(callErr) != 0:
			restoreErr = fmt.Errorf(
				"restore SeBackupPrivilege returned Windows error %d: %w",
				containmentWindowsErrorCodeServer2022(callErr),
				containmentNormalizeCallErrorServer2022(callErr),
			)
		}
	}

	closeErr := syscall.CloseHandle(scope.Token)
	if closeErr != nil {
		closeErr = fmt.Errorf(
			"close SeBackupPrivilege process token: %w",
			closeErr,
		)
	}

	return errors.Join(restoreErr, closeErr)
}

func containmentServer2022() bool {
	var version containmentOSVersionInfo
	version.Size = uint32(unsafe.Sizeof(version))

	status, _, _ := procContainmentRtlGetVersion.Call(
		uintptr(unsafe.Pointer(&version)),
	)
	if status != 0 {
		return false
	}

	return containmentIsServer2022Version(
		version.MajorVersion,
		version.MinorVersion,
		version.BuildNumber,
	)
}

func containmentWindowsErrorCodeServer2022(err error) uint32 {
	if err == nil {
		return 0
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		return uint32(errno)
	}
	return 0
}
