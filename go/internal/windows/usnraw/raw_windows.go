// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnraw

import (
	"errors"
	"strings"
	"syscall"
	"unsafe"
)

const (
	fileReadData         = 0x00000001
	fsctlQueryUSNJournal = 0x000900F4
	fsctlReadUSNJournal  = 0x000900BB
	readBufferSize       = 1024 * 1024
)

var (
	ErrInvalidGovernedRoot = errors.New("governed root must use a local drive-absolute path")
	ErrMalformedUSNBuffer  = errors.New("Windows returned a malformed USN journal buffer")
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procDeviceIoControl = kernel32.NewProc("DeviceIoControl")
)

type Journal struct {
	JournalID       uint64
	FirstUSN        int64
	NextUSN         int64
	LowestValidUSN  int64
	MaxUSN          int64
	MaximumSize     uint64
	AllocationDelta uint64
}

type readJournalDataV0 struct {
	StartUSN          int64
	ReasonMask        uint32
	ReturnOnlyOnClose uint32
	Timeout           uint64
	BytesToWaitFor    uint64
	JournalID         uint64
}

var (
	_ [56 - unsafe.Sizeof(Journal{})]byte
	_ [unsafe.Sizeof(Journal{}) - 56]byte
	_ [40 - unsafe.Sizeof(readJournalDataV0{})]byte
	_ [unsafe.Sizeof(readJournalDataV0{}) - 40]byte
)

// DriveForRoot returns the local drive letter containing governedRoot.
func DriveForRoot(governedRoot string) (string, error) {
	switch {
	case len(governedRoot) >= 3 && isASCIILetter(governedRoot[0]) && governedRoot[1] == ':' && governedRoot[2] == '\\':
		return strings.ToUpper(string(governedRoot[0])), nil
	case len(governedRoot) >= 7 && strings.HasPrefix(governedRoot, `\\?\`) && isASCIILetter(governedRoot[4]) && governedRoot[5] == ':' && governedRoot[6] == '\\':
		return strings.ToUpper(string(governedRoot[4])), nil
	default:
		return "", ErrInvalidGovernedRoot
	}
}

// Query opens the raw NTFS volume containing governedRoot and returns the
// current USN journal state. It does not create, resize, delete, or otherwise
// modify the journal.
func Query(governedRoot string) (Journal, error) {
	handle, err := openVolumeForRoot(governedRoot)
	if err != nil {
		return Journal{}, err
	}
	defer syscall.CloseHandle(handle)

	return queryJournalNative(handle)
}

// Read opens the raw NTFS volume containing governedRoot, queries the current
// journal identifier, and returns one bounded raw USN buffer beginning at
// startUSN. Parsing intentionally remains outside this privileged package.
func Read(governedRoot string, startUSN int64) (Journal, []byte, error) {
	if startUSN < 0 {
		return Journal{}, nil, errors.New("start USN must not be negative")
	}

	handle, err := openVolumeForRoot(governedRoot)
	if err != nil {
		return Journal{}, nil, err
	}
	defer syscall.CloseHandle(handle)

	journal, err := queryJournalNative(handle)
	if err != nil {
		return Journal{}, nil, err
	}
	buffer, err := readJournalNative(handle, startUSN, journal.JournalID)
	if err != nil {
		return Journal{}, nil, err
	}
	return journal, buffer, nil
}

func isASCIILetter(value byte) bool {
	return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z')
}

func openVolumeForRoot(governedRoot string) (syscall.Handle, error) {
	drive, err := DriveForRoot(governedRoot)
	if err != nil {
		return syscall.InvalidHandle, err
	}

	devicePath := `\\.\` + drive + `:`
	deviceUnits, err := syscall.UTF16PtrFromString(devicePath)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	return syscall.CreateFile(
		deviceUnits,
		fileReadData,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		0,
		0,
	)
}

func queryJournalNative(handle syscall.Handle) (Journal, error) {
	var journal Journal
	var returned uint32
	r1, _, callErr := procDeviceIoControl.Call(
		uintptr(handle),
		fsctlQueryUSNJournal,
		0,
		0,
		uintptr(unsafe.Pointer(&journal)),
		unsafe.Sizeof(journal),
		uintptr(unsafe.Pointer(&returned)),
		0,
	)
	if r1 == 0 {
		return Journal{}, callErr
	}
	if returned < uint32(unsafe.Sizeof(journal)) {
		return Journal{}, ErrMalformedUSNBuffer
	}
	if journal.FirstUSN < 0 || journal.NextUSN < 0 || journal.LowestValidUSN < 0 || journal.MaxUSN < 0 {
		return Journal{}, ErrMalformedUSNBuffer
	}
	return journal, nil
}

func readJournalNative(handle syscall.Handle, startUSN int64, journalID uint64) ([]byte, error) {
	request := readJournalDataV0{
		StartUSN:          startUSN,
		ReasonMask:        0xFFFFFFFF,
		ReturnOnlyOnClose: 0,
		Timeout:           0,
		BytesToWaitFor:    0,
		JournalID:         journalID,
	}
	buffer := make([]byte, readBufferSize)
	var returned uint32
	r1, _, callErr := procDeviceIoControl.Call(
		uintptr(handle),
		fsctlReadUSNJournal,
		uintptr(unsafe.Pointer(&request)),
		unsafe.Sizeof(request),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&returned)),
		0,
	)
	if r1 == 0 {
		return nil, callErr
	}
	if returned < 8 || returned > uint32(len(buffer)) {
		return nil, ErrMalformedUSNBuffer
	}
	return append([]byte(nil), buffer[:returned]...), nil
}
