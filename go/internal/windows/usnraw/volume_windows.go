// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnraw

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	// FSCTL_GET_NTFS_VOLUME_DATA is a read-only native request that returns
	// NTFS_VOLUME_DATA_BUFFER, beginning with the 64-bit volume serial.
	// Using the SAME raw-volume handle for this check and the later USN FSCTLs
	// prevents a separate path lookup from supplying an unbound identity.
	fsctlGetNTFSVolumeData = 0x00090064
	ntfsVolumeDataBufferSize = 96
)

var errEnrolledVolumeIdentity = errors.New("FI enrolled NTFS volume identity mismatch")

// QueryEnrolledVolume accesses only the GUID/serial target selected by the
// broker's immutable operator-approved enrollment snapshot. The raw-volume
// handle is re-attested on each request before the USN journal is queried.
func QueryEnrolledVolume(volumeGUID, expectedSerial string) (Journal, error) {
	handle, err := openAndVerifyEnrolledVolume(volumeGUID, expectedSerial)
	if err != nil {
		return Journal{}, err
	}
	defer syscall.CloseHandle(handle)
	return queryJournalNative(handle)
}

// ReadEnrolledVolume is bounded by the existing 1 MiB USN read buffer. It
// queries the current journal ID on the verified raw-volume handle and uses
// that ID for the same-handle read. Only the collector may later establish
// historical continuity and advance a verified custody checkpoint.
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

// enrolledVolumeDevicePath validates a Windows-managed volume GUID path and
// its full 64-bit NTFS serial. Removing ONLY the final backslash yields the
// device path, rather than opening the volume's root directory. It does not
// accept drive letters, physical drives, UNC paths or arbitrary raw targets.
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

// verifyNTFSVolumeDataBuffer validates an exact native response length before
// inspecting its 64-bit serial. No 32-bit fallback is permitted. This helper
// is testable without privileged volume access.
func verifyNTFSVolumeDataBuffer(data []byte, returned uint32, expected uint64) error {
	if len(data) < ntfsVolumeDataBufferSize || returned < ntfsVolumeDataBufferSize ||
		int(returned) > len(data) {
		return errors.New("FSCTL_GET_NTFS_VOLUME_DATA returned a malformed NTFS_VOLUME_DATA_BUFFER")
	}
	observed := binary.LittleEndian.Uint64(data[:8])
	if observed != expected {
		return fmt.Errorf("%w: expected full-width serial %d, observed %d",
			errEnrolledVolumeIdentity, expected, observed)
	}
	return nil
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
		fileReadData, // existing characterized narrow raw-USN access right
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
	if err != nil {
		return syscall.InvalidHandle, fmt.Errorf("open approved NTFS volume for USN: %w", err)
	}

	var data [ntfsVolumeDataBufferSize]byte
	var returned uint32
	ok, _, callErr := procDeviceIoControl.Call(
		uintptr(handle),
		fsctlGetNTFSVolumeData,
		0,
		0,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&returned)),
		0,
	)
	if ok == 0 {
		syscall.CloseHandle(handle)
		return syscall.InvalidHandle, fmt.Errorf("attest NTFS serial on opened USN volume: %w", callErr)
	}
	if err := verifyNTFSVolumeDataBuffer(data[:], returned, expected); err != nil {
		syscall.CloseHandle(handle)
		return syscall.InvalidHandle, err
	}
	return handle, nil
}
