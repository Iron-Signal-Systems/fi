// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package securityevent

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

var (
	scopeKernel32                          = syscall.NewLazyDLL("kernel32.dll")
	scopeQueryDosDeviceW                   = scopeKernel32.NewProc("QueryDosDeviceW")
	scopeGetVolumeNameForVolumeMountPointW = scopeKernel32.NewProc("GetVolumeNameForVolumeMountPointW")
)

// ExpandGovernedScopes resolves the configured drive letter to its current,
// OS-reported NT device and volume-GUID paths. Failure to resolve a drive is
// fatal to this Security collection pass: never advance the Security checkpoint
// with an unverified set of aliases.
func ExpandGovernedScopes(scopes []GovernedScope) ([]GovernedScope, error) {
	result := make([]GovernedScope, len(scopes))
	for i, scope := range scopes {
		result[i] = scope
		if len(scope.GovernedRoot) < 3 ||
			!isDriveLetter(scope.GovernedRoot[0]) ||
			scope.GovernedRoot[1] != ':' ||
			(scope.GovernedRoot[2] != '\\' && scope.GovernedRoot[2] != '/') {
			// Non-drive roots continue to use the preexisting exact path matcher.
			continue
		}

		drive := strings.ToUpper(scope.GovernedRoot[:2])
		device, err := queryScopeDosDevice(drive)
		if err != nil {
			return nil, fmt.Errorf("resolve Security governed root %q NT device: %w", scope.GovernedRoot, err)
		}
		volume, err := queryScopeVolumeGUID(drive + `\`)
		if err != nil {
			return nil, fmt.Errorf("resolve Security governed root %q volume GUID: %w", scope.GovernedRoot, err)
		}
		aliases, err := driveRootAliases(scope.GovernedRoot, device, volume)
		if err != nil {
			return nil, err
		}
		result[i].Aliases = append(append([]string(nil), scope.Aliases...), aliases...)
	}
	return result, nil
}

func queryScopeDosDevice(drive string) (string, error) {
	input, err := syscall.UTF16PtrFromString(drive)
	if err != nil {
		return "", err
	}
	// QueryDosDevice returns MULTI_SZ. The first mapping is the active mapping.
	buffer := make([]uint16, 32768)
	r1, _, callErr := scopeQueryDosDeviceW.Call(
		uintptr(unsafe.Pointer(input)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
	)
	if r1 == 0 {
		return "", fmt.Errorf("QueryDosDeviceW(%s): %w", drive, callErr)
	}
	device := syscall.UTF16ToString(buffer[:int(r1)])
	if device == "" {
		return "", fmt.Errorf("QueryDosDeviceW(%s): empty mapping", drive)
	}
	return device, nil
}

func queryScopeVolumeGUID(driveRoot string) (string, error) {
	input, err := syscall.UTF16PtrFromString(driveRoot)
	if err != nil {
		return "", err
	}
	buffer := make([]uint16, 256)
	r1, _, callErr := scopeGetVolumeNameForVolumeMountPointW.Call(
		uintptr(unsafe.Pointer(input)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
	)
	if r1 == 0 {
		return "", fmt.Errorf("GetVolumeNameForVolumeMountPointW(%s): %w", driveRoot, callErr)
	}
	return syscall.UTF16ToString(buffer), nil
}
