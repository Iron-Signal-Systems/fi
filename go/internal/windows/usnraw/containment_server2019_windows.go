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
	containmentServer2019Major = 10
	containmentServer2019Minor = 0
	containmentServer2019Build = 17763
)

// containmentCheckServer2019 is the Windows Server 2019 build 17763 fallback
// for protected system objects that return ERROR_ACCESS_DENIED from the normal
// zero-access OpenFileById containment call.
//
// Server 2019 build 17763.9245 was independently characterized with the same
// bounded behavior already validated for Server 2022 build 20348: temporarily
// enable SeBackupPrivilege, retry the exact same zero-access OpenFileById once,
// resolve only mechanical governed-root containment, and restore the exact
// previous privilege state before returning.
//
// Keep the implementation shared with the validated Server 2022 path so the
// characterized releases cannot silently drift in privilege behavior.
func containmentCheckServer2019(
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

func containmentIsServer2019Version(major, minor, build uint32) bool {
	return major == containmentServer2019Major &&
		minor == containmentServer2019Minor &&
		build == containmentServer2019Build
}

func containmentServer2019() bool {
	var version containmentOSVersionInfo
	version.Size = uint32(unsafe.Sizeof(version))

	status, _, _ := procContainmentRtlGetVersion.Call(
		uintptr(unsafe.Pointer(&version)),
	)
	if status != 0 {
		return false
	}

	return containmentIsServer2019Version(
		version.MajorVersion,
		version.MinorVersion,
		version.BuildNumber,
	)
}
