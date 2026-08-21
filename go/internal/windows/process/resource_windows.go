// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package process

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	kernel32             = syscall.NewLazyDLL("kernel32.dll")
	psapi                = syscall.NewLazyDLL("psapi.dll")
	ntdll                = syscall.NewLazyDLL("ntdll.dll")
	procGetProcessTimes  = kernel32.NewProc("GetProcessTimes")
	procGetProcessMemory = psapi.NewProc("GetProcessMemoryInfo")
	procRtlGetVersion    = ntdll.NewProc("RtlGetVersion")
)

// Snapshot records process-wide resource counters available from Windows.
type Snapshot struct {
	CPU100Nanoseconds   uint64
	PeakWorkingSetBytes uint64
	WorkingSetBytes     uint64
	PrivateBytes        uint64
}

type processMemoryCountersEx struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
	PrivateUsage               uintptr
}

type rtlOSVersionInfoEx struct {
	OSVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformID        uint32
	CSDVersion        [128]uint16
	ServicePackMajor  uint16
	ServicePackMinor  uint16
	SuiteMask         uint16
	ProductType       byte
	Reserved          byte
}

// Current returns resource counters for the current FI process.
func Current() (Snapshot, error) {
	handle, err := syscall.GetCurrentProcess()
	if err != nil {
		return Snapshot{}, fmt.Errorf("GetCurrentProcess: %w", err)
	}

	var memory processMemoryCountersEx
	memory.CB = uint32(unsafe.Sizeof(memory))
	result, _, callErr := procGetProcessMemory.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&memory)),
		uintptr(memory.CB),
	)
	if result == 0 {
		return Snapshot{}, windowsCallError("GetProcessMemoryInfo", callErr)
	}

	var creation syscall.Filetime
	var exit syscall.Filetime
	var kernel syscall.Filetime
	var user syscall.Filetime
	result, _, callErr = procGetProcessTimes.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&creation)),
		uintptr(unsafe.Pointer(&exit)),
		uintptr(unsafe.Pointer(&kernel)),
		uintptr(unsafe.Pointer(&user)),
	)
	if result == 0 {
		return Snapshot{}, windowsCallError("GetProcessTimes", callErr)
	}

	return Snapshot{
		CPU100Nanoseconds:   filetime100Nanoseconds(kernel) + filetime100Nanoseconds(user),
		PeakWorkingSetBytes: uint64(memory.PeakWorkingSetSize),
		WorkingSetBytes:     uint64(memory.WorkingSetSize),
		PrivateBytes:        uint64(memory.PrivateUsage),
	}, nil
}

// WindowsVersion returns the actual NT kernel version reported by RtlGetVersion.
func WindowsVersion() (string, error) {
	var version rtlOSVersionInfoEx
	version.OSVersionInfoSize = uint32(unsafe.Sizeof(version))
	status, _, _ := procRtlGetVersion.Call(uintptr(unsafe.Pointer(&version)))
	if status != 0 {
		return "", fmt.Errorf("RtlGetVersion: NTSTATUS 0x%08X", uint32(status))
	}
	return fmt.Sprintf("%d.%d.%d", version.MajorVersion, version.MinorVersion, version.BuildNumber), nil
}

func filetime100Nanoseconds(value syscall.Filetime) uint64 {
	return uint64(value.HighDateTime)<<32 | uint64(value.LowDateTime)
}

func windowsCallError(operation string, err error) error {
	if errno, ok := err.(syscall.Errno); ok && errno == 0 {
		return fmt.Errorf("%s failed", operation)
	}
	return fmt.Errorf("%s: %w", operation, err)
}
