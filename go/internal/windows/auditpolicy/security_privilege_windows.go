// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package auditpolicy

import (
	"errors"
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

const (
	tokenAdjustPrivileges = 0x0020
	tokenQuery            = 0x0008
	sePrivilegeEnabled    = 0x00000002
	errorNotAllAssigned   = syscall.Errno(1300)
)

type privilegeLUID struct {
	LowPart  uint32
	HighPart int32
}

type tokenPrivileges struct {
	PrivilegeCount uint32
	LUID           privilegeLUID
	Attributes     uint32
}

var (
	_ [16 - unsafe.Sizeof(tokenPrivileges{})]byte
	_ [unsafe.Sizeof(tokenPrivileges{}) - 16]byte
)

var (
	privilegeMutex        sync.Mutex
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	getCurrentProcess     = kernel32.NewProc("GetCurrentProcess")
	closeHandle           = kernel32.NewProc("CloseHandle")
	openProcessToken      = advapi32.NewProc("OpenProcessToken")
	lookupPrivilegeValue  = advapi32.NewProc("LookupPrivilegeValueW")
	adjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")
)

// withSecurityPrivilege activates an already-assigned SeSecurityPrivilege and
// restores its previous state. It cannot add a privilege to the service token.
// The process token is shared, so avoid concurrent transitions in this package.
func withSecurityPrivilege(work func() error) (resultErr error) {
	privilegeMutex.Lock()
	defer privilegeMutex.Unlock()

	process, _, _ := getCurrentProcess.Call()
	var token uintptr
	ok, _, callErr := openProcessToken.Call(process, tokenAdjustPrivileges|tokenQuery, uintptr(unsafe.Pointer(&token)))
	if ok == 0 {
		return apiError("OpenProcessToken", callErr)
	}
	defer closeHandle.Call(token)

	name, err := syscall.UTF16PtrFromString("SeSecurityPrivilege")
	if err != nil {
		return err
	}
	var luid privilegeLUID
	ok, _, callErr = lookupPrivilegeValue.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&luid)))
	if ok == 0 {
		return apiError("LookupPrivilegeValueW", callErr)
	}

	desired := tokenPrivileges{PrivilegeCount: 1, LUID: luid, Attributes: sePrivilegeEnabled}
	var previous tokenPrivileges
	var previousLength uint32
	ok, _, callErr = adjustTokenPrivileges.Call(
		token, 0, uintptr(unsafe.Pointer(&desired)), unsafe.Sizeof(previous),
		uintptr(unsafe.Pointer(&previous)), uintptr(unsafe.Pointer(&previousLength)),
	)
	if ok == 0 {
		return apiError("AdjustTokenPrivileges(enable)", callErr)
	}
	if errors.Is(callErr, errorNotAllAssigned) {
		return fmt.Errorf("SeSecurityPrivilege is not assigned to current FI privileged service token: %w", callErr)
	}
	defer func() {
		if previous.PrivilegeCount == 0 {
			return
		}
		ok, _, restoreErr := adjustTokenPrivileges.Call(
			token, 0, uintptr(unsafe.Pointer(&previous)), 0, 0, 0,
		)
		if ok == 0 {
			resultErr = errors.Join(resultErr, apiError("AdjustTokenPrivileges(restore)", restoreErr))
		}
	}()
	return work()
}
