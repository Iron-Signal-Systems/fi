// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnraw

import (
	"syscall"
	"unsafe"
)

const (
	containmentServer2025Major = 10
	containmentServer2025Minor = 0
	containmentServer2025Build = 26100
)

// containmentCheckServer2025 is the Windows Server 2025 build 26100 fallback
// for protected system objects that return ERROR_ACCESS_DENIED from the normal
// zero-access OpenFileById containment call.
//
// Build 26100 was independently characterized with the same bounded behavior as
// Server 2022 build 20348: temporarily enable SeBackupPrivilege, retry the exact
// same zero-access OpenFileById once, resolve only mechanical containment, and
// restore the exact previous privilege state before returning.
//
// Keep the implementation shared with the already validated Server 2022 path so
// the two validated releases cannot silently drift in privilege behavior.
func containmentCheckServer2025(
	rootHandle syscall.Handle,
	rootPath string,
	fileReferenceNumber uint64,
	sequenceNumber uint16,
) (ContainmentResult, error) {
	return containmentCheckServer2022(
		rootHandle,
		rootPath,
		fileReferenceNumber,
		sequenceNumber,
	)
}

func containmentIsServer2025Version(major, minor, build uint32) bool {
	return major == containmentServer2025Major &&
		minor == containmentServer2025Minor &&
		build == containmentServer2025Build
}

func containmentServer2025() bool {
	var version containmentOSVersionInfo
	version.Size = uint32(unsafe.Sizeof(version))

	status, _, _ := procContainmentRtlGetVersion.Call(
		uintptr(unsafe.Pointer(&version)),
	)
	if status != 0 {
		return false
	}

	return containmentIsServer2025Version(
		version.MajorVersion,
		version.MinorVersion,
		version.BuildNumber,
	)
}
