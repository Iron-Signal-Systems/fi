// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	errorNotAllAssigned syscall.Errno = 1300
)

var (
	advapi32PrivilegeDLL = windows.NewLazySystemDLL(
		"advapi32.dll",
	)
	adjustTokenPrivilegesProc = advapi32PrivilegeDLL.NewProc(
		"AdjustTokenPrivileges",
	)
)

func withEnabledProcessPrivilege(
	name string,
	run func() error,
) error {
	if run == nil {
		return fmt.Errorf(
			"privileged operation callback is required",
		)
	}

	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|
			windows.TOKEN_QUERY,
		&token,
	); err != nil {
		return fmt.Errorf(
			"open current process token for %s: %w",
			name,
			err,
		)
	}
	defer windows.CloseHandle(
		windows.Handle(
			token,
		),
	)

	namePointer, err := windows.UTF16PtrFromString(
		name,
	)
	if err != nil {
		return fmt.Errorf(
			"encode privilege %s: %w",
			name,
			err,
		)
	}

	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(
		nil,
		namePointer,
		&luid,
	); err != nil {
		return fmt.Errorf(
			"lookup privilege %s: %w",
			name,
			err,
		)
	}

	desired := windows.Tokenprivileges{
		PrivilegeCount: 1,
	}
	desired.Privileges[0] = windows.LUIDAndAttributes{
		Luid:       luid,
		Attributes: windows.SE_PRIVILEGE_ENABLED,
	}

	var previous windows.Tokenprivileges
	var previousLength uint32

	result, _, lastErr := adjustTokenPrivilegesProc.Call(
		uintptr(
			token,
		),
		0,
		uintptr(
			unsafe.Pointer(
				&desired,
			),
		),
		unsafe.Sizeof(
			previous,
		),
		uintptr(
			unsafe.Pointer(
				&previous,
			),
		),
		uintptr(
			unsafe.Pointer(
				&previousLength,
			),
		),
	)
	if result == 0 {
		return fmt.Errorf(
			"enable process privilege %s: %w",
			name,
			lastErr,
		)
	}
	if errors.Is(
		lastErr,
		errorNotAllAssigned,
	) {
		return fmt.Errorf(
			"enable process privilege %s: current process token does not contain the privilege",
			name,
		)
	}

	runErr := run()

	var restoreErr error
	if previous.PrivilegeCount != 0 {
		result, _, lastErr = adjustTokenPrivilegesProc.Call(
			uintptr(
				token,
			),
			0,
			uintptr(
				unsafe.Pointer(
					&previous,
				),
			),
			0,
			0,
			0,
		)
		if result == 0 {
			restoreErr = fmt.Errorf(
				"restore process privilege %s state: %w",
				name,
				lastErr,
			)
		} else if errors.Is(
			lastErr,
			errorNotAllAssigned,
		) {
			restoreErr = fmt.Errorf(
				"restore process privilege %s state: current process token no longer contains the privilege",
				name,
			)
		}
	}

	if runErr != nil && restoreErr != nil {
		return fmt.Errorf(
			"%w; additionally failed to restore process privilege state: %v",
			runErr,
			restoreErr,
		)
	}
	if runErr != nil {
		return runErr
	}
	return restoreErr
}
