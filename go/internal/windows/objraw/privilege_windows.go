// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package objraw

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	backupPrivilegeEnabled           = 0x00000002
	backupTokenAdjustPrivileges      = 0x00000020
	backupTokenQuery                 = 0x00000008
	backupWindowsErrorNotAllAssigned = syscall.Errno(1300)
)

var ErrBackupPrivilegeUnavailable = errors.New("FIObjReader SeBackupPrivilege unavailable")

type backupLUID struct {
	LowPart  uint32
	HighPart int32
}

type backupLUIDAndAttributes struct {
	LUID       backupLUID
	Attributes uint32
}

type backupPrivilegeScope struct {
	Token         syscall.Handle
	Previous      backupTokenPrivileges
	RestoreNeeded bool
}

type backupTokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [1]backupLUIDAndAttributes
}

var (
	backupAdvapi32                  = syscall.NewLazyDLL("advapi32.dll")
	backupKernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procBackupAdjustTokenPrivileges = backupAdvapi32.NewProc("AdjustTokenPrivileges")
	procBackupGetCurrentProcess     = backupKernel32.NewProc("GetCurrentProcess")
	procBackupLookupPrivilegeValueW = backupAdvapi32.NewProc("LookupPrivilegeValueW")
	procBackupOpenProcessToken      = backupAdvapi32.NewProc("OpenProcessToken")
	procBackupSetLastError          = backupKernel32.NewProc("SetLastError")
)

func backupNormalizeCallError(err error) error {
	if err == nil {
		return errors.New("Windows call failed without an error code")
	}
	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return errors.New("Windows call failed without an error code")
	}
	return err
}

func backupWindowsErrorCode(err error) uint32 {
	if err == nil {
		return 0
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		return uint32(errno)
	}
	return 0
}

func enableBackupPrivilege() (backupPrivilegeScope, error) {
	process, _, _ := procBackupGetCurrentProcess.Call()

	var token syscall.Handle
	result, _, callErr := procBackupOpenProcessToken.Call(
		process,
		uintptr(backupTokenAdjustPrivileges|backupTokenQuery),
		uintptr(unsafe.Pointer(&token)),
	)
	if result == 0 {
		return backupPrivilegeScope{}, fmt.Errorf(
			"open FIObjReader process token for SeBackupPrivilege: %w",
			backupNormalizeCallError(callErr),
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
		return backupPrivilegeScope{}, fmt.Errorf(
			"UTF16PtrFromString(SeBackupPrivilege): %w",
			err,
		)
	}

	var privilegeLUID backupLUID
	result, _, callErr = procBackupLookupPrivilegeValueW.Call(
		0,
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&privilegeLUID)),
	)
	if result == 0 {
		return backupPrivilegeScope{}, fmt.Errorf(
			"lookup SeBackupPrivilege: %w",
			backupNormalizeCallError(callErr),
		)
	}

	newState := backupTokenPrivileges{
		PrivilegeCount: 1,
		Privileges: [1]backupLUIDAndAttributes{{
			LUID:       privilegeLUID,
			Attributes: backupPrivilegeEnabled,
		}},
	}

	var previous backupTokenPrivileges
	var previousLength uint32

	_, _, _ = procBackupSetLastError.Call(0)

	result, _, callErr = procBackupAdjustTokenPrivileges.Call(
		uintptr(token),
		0,
		uintptr(unsafe.Pointer(&newState)),
		unsafe.Sizeof(previous),
		uintptr(unsafe.Pointer(&previous)),
		uintptr(unsafe.Pointer(&previousLength)),
	)
	runtime.KeepAlive(&newState)
	if result == 0 {
		return backupPrivilegeScope{}, fmt.Errorf(
			"enable SeBackupPrivilege: %w",
			backupNormalizeCallError(callErr),
		)
	}

	switch code := backupWindowsErrorCode(callErr); code {
	case 0:
		closeOnError = false
		return backupPrivilegeScope{
			Token:         token,
			Previous:      previous,
			RestoreNeeded: previous.PrivilegeCount > 0,
		}, nil

	case uint32(backupWindowsErrorNotAllAssigned):
		return backupPrivilegeScope{}, fmt.Errorf(
			"%w: Windows error %d",
			ErrBackupPrivilegeUnavailable,
			code,
		)

	default:
		return backupPrivilegeScope{}, fmt.Errorf(
			"enable SeBackupPrivilege returned Windows error %d: %w",
			code,
			backupNormalizeCallError(callErr),
		)
	}
}

func restoreBackupPrivilege(scope backupPrivilegeScope) error {
	if scope.Token == 0 || scope.Token == syscall.InvalidHandle {
		return errors.New("restore SeBackupPrivilege: process token handle is invalid")
	}

	var restoreErr error
	if scope.RestoreNeeded {
		_, _, _ = procBackupSetLastError.Call(0)

		result, _, callErr := procBackupAdjustTokenPrivileges.Call(
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
				"restore SeBackupPrivilege: %w",
				backupNormalizeCallError(callErr),
			)

		case backupWindowsErrorCode(callErr) != 0:
			restoreErr = fmt.Errorf(
				"restore SeBackupPrivilege returned Windows error %d: %w",
				backupWindowsErrorCode(callErr),
				backupNormalizeCallError(callErr),
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
