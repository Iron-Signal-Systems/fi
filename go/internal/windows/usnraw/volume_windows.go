// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnraw

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

var (
	errEnrolledVolumeIdentity = errors.New("FI enrolled NTFS volume identity mismatch")
	procUSNVolumeGetFileInformationByHandleEx = kernel32.NewProc("GetFileInformationByHandleEx")
	procUSNVolumeGetVolumeInformationByHandleW = kernel32.NewProc("GetVolumeInformationByHandleW")
)

// FILE_ID_INFO uses the full 64-bit volume serial, not the 32-bit serial
// returned by GetVolumeInformationByHandleW.
type enrolledVolumeFileIDInfo struct {
	VolumeSerial uint64
	FileID       [16]byte
}

var (
	_ [24 - unsafe.Sizeof(enrolledVolumeFileIDInfo{})]byte
	_ [unsafe.Sizeof(enrolledVolumeFileIDInfo{}) - 24]byte
)

// QueryEnrolledVolume queries only an explicitly authorized NTFS volume. The
// caller must be the authenticated broker dispatcher, which resolves an ID
// against administrator-approved local configuration. This package still
// validates exact GUID syntax and re-attests the full 64-bit volume identity
// on the SAME raw-volume handle used for DeviceIoControl.
func QueryEnrolledVolume(volumeGUID, expectedSerial string) (Journal, error) {
	handle, err := openAndVerifyEnrolledVolume(volumeGUID, expectedSerial)
	if err != nil {
		return Journal{}, err
	}
	defer syscall.CloseHandle(handle)
	return queryJournalNative(handle)
}

// ReadEnrolledVolume is bounded by the existing 1 MiB USN read buffer. It
// queries the journal ID on the verified volume handle and passes that ID in
// the native read request. The unprivileged collector owns continuity, record
// parsing, durability and subsequent checkpoint decisions.
func ReadEnrolledVolume(volumeGUID, expectedSerial string, startUSN int64) (Journal, []byte, error) {
	if startUSN < 0 {
		return Journal{}, nil, errors.New("volume USN start cursor must not be negative")
	}
	handle, err := openAndVerifyEnrolledVolume(volumeGUID, expectedSerial)
	if err != nil {
		return Journal{}, nil, err
	}
	defer syscall.CloseHandle(handle)
	journal, err := queryJournalNative(handle)
	if err != nil {
		return Journal{}, nil, err
	}
	data, err := readJournalNative(handle, startUSN, journal.JournalID)
	if err != nil {
		return Journal{}, nil, err
	}
	return journal, data, nil
}

// enrolledVolumeDevicePath returns a Windows native VOLUME device locator,
// not a drive-letter or caller-provided raw disk path. Removing exactly the
// final backslash is required to open the volume rather than its root folder.
func enrolledVolumeDevicePath(guid, serial string) (string, uint64, error) {
	const prefix = `\\?\Volume{`
	const suffix = `}\`
	if len(guid) != len(prefix)+36+len(suffix) ||
		!strings.EqualFold(guid[:min(len(guid), len(prefix))], prefix) ||
		!strings.HasSuffix(guid, suffix) {
		return "", 0, errors.New("enrolled USN target requires an exact Windows volume GUID path")
	}
	raw := guid[len(prefix) : len(prefix)+36]
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return "", 0, errors.New("enrolled volume GUID has invalid separators")
			}
		} else if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return "", 0, errors.New("enrolled volume GUID has nonhexadecimal characters")
		}
	}
	if serial == "" || serial[0] < '1' || serial[0] > '9' {
		return "", 0, errors.New("enrolled volume serial must be nonzero canonical decimal")
	}
	for i := 1; i < len(serial); i++ {
		if serial[i] < '0' || serial[i] > '9' {
			return "", 0, errors.New("enrolled volume serial must be canonical decimal")
		}
	}
	id, err := strconv.ParseUint(serial, 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("enrolled volume serial overflow: %w", err)
	}
	return prefix + strings.ToLower(raw) + "}", id, nil
}

func openAndVerifyEnrolledVolume(guid, serial string) (syscall.Handle, error) {
	rawPath, expected, err := enrolledVolumeDevicePath(guid, serial)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	units, err := syscall.UTF16PtrFromString(rawPath)
	if err != nil {
		return syscall.InvalidHandle, fmt.Errorf("encode enrolled NTFS volume: %w", err)
	}
	handle, err := syscall.CreateFile(
		units,
		fileReadData, // same least-tested raw USN access right as root-era path
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return syscall.InvalidHandle, fmt.Errorf("open approved NTFS volume for USN: %w", err)
	}
	var fsName [32]uint16
	ok, _, callErr := procUSNVolumeGetVolumeInformationByHandleW.Call(
		uintptr(handle),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&fsName[0])),
		uintptr(len(fsName)),
	)
	if ok == 0 {
		syscall.CloseHandle(handle)
		return syscall.InvalidHandle, fmt.Errorf("attest filesystem on opened USN volume: %w", callErr)
	}
	if !strings.EqualFold(syscall.UTF16ToString(fsName[:]), "NTFS") {
		syscall.CloseHandle(handle)
		return syscall.InvalidHandle, fmt.Errorf("%w: opened volume is not NTFS", errEnrolledVolumeIdentity)
	}
	var info enrolledVolumeFileIDInfo
	ok, _, callErr = procUSNVolumeGetFileInformationByHandleEx.Call(
		uintptr(handle),
		18, // FileIdInfo
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if ok == 0 {
		syscall.CloseHandle(handle)
		// No fallback to the truncated 32-bit serial or a separately
		// opened directory handle: identity must be attested on the handle
		// that actually issues the privileged DeviceIoControl request.
		return syscall.InvalidHandle, fmt.Errorf("attest full-width serial on opened USN volume: %w", callErr)
	}
	if info.VolumeSerial != expected {
		syscall.CloseHandle(handle)
		return syscall.InvalidHandle, fmt.Errorf("%w: expected serial %d, observed %d", errEnrolledVolumeIdentity, expected, info.VolumeSerial)
	}
	return handle, nil
}
