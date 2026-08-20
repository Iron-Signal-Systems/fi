// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"
)

// This file is the Windows API boundary for direct NTFS collection. Native
// Windows constants and ABI structures stay here so unsafe/syscall handling
// does not spread through the rest of the collector.

const (
	// fileReadAttributes is the access FI requests for its own handle.
	// It does not grant write access.
	fileReadAttributes = 0x0080

	fileNameNormalized = 0x0000
	volumeNameGUID     = 0x0001

	fileBasicInfoClass    = 0
	fileStandardInfoClass = 1
	fileStreamInfoClass   = 7
	fileIdInfoClass       = 18

	fileAttributeDirectory = 0x00000010
	fileAttributeReparse   = 0x00000400

	// Stream enumeration grows only to this fixed ceiling so a malformed or
	// hostile source cannot make FI allocate without bound.
	initialStreamInfoBuffer = 64 * 1024
	maximumStreamInfoBuffer = 4 * 1024 * 1024
	fileStreamInfoHeader    = 24
)

const (
	errorInsufficientBuffer syscall.Errno = 122
	errorMoreData           syscall.Errno = 234
	errorHandleEOF          syscall.Errno = 38
)

var (
	kernel32                          = syscall.NewLazyDLL("kernel32.dll")
	procGetFileInformationByHandleEx  = kernel32.NewProc("GetFileInformationByHandleEx")
	procGetVolumeInformationByHandleW = kernel32.NewProc("GetVolumeInformationByHandleW")
	procGetFinalPathNameByHandleW     = kernel32.NewProc("GetFinalPathNameByHandleW")
)

// The structures below match the fixed Windows ABI layouts passed directly to
// Kernel32. Keep Windows layout details in this file.
type fileBasicInfo struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangeTime     int64
	FileAttributes uint32
	_              [4]byte
}

type fileStandardInfo struct {
	AllocationSize int64
	EndOfFile      int64
	NumberOfLinks  uint32
	DeletePending  uint8
	Directory      uint8
	_              [2]byte
}

type fileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

type nativeState struct {
	Basic    fileBasicInfo
	Standard fileStandardInfo
	ID       fileIDInfo
}

type nativeStream struct {
	Name           []uint16
	Size           int64
	AllocationSize int64
}

// Compile-time ABI checks. A build fails if Go lays out one of the fixed
// Windows structures at an unexpected size.
var (
	_ [40 - unsafe.Sizeof(fileBasicInfo{})]byte
	_ [unsafe.Sizeof(fileBasicInfo{}) - 40]byte
	_ [24 - unsafe.Sizeof(fileStandardInfo{})]byte
	_ [unsafe.Sizeof(fileStandardInfo{}) - 24]byte
	_ [24 - unsafe.Sizeof(fileIDInfo{})]byte
	_ [unsafe.Sizeof(fileIDInfo{}) - 24]byte
)

// openPath opens an existing Windows filesystem object for metadata inspection.
//
// FI requests FILE_READ_ATTRIBUTES only for its own handle.
//
// FILE_SHARE_READ, FILE_SHARE_WRITE, and FILE_SHARE_DELETE do NOT grant FI
// read/write/delete access. They allow other processes to continue reading,
// writing, renaming, or deleting the object while FI has it open. FI observes
// production state without locking normal workloads.
//
// OPEN_EXISTING prevents creation/truncation. FILE_FLAG_BACKUP_SEMANTICS allows
// directories to be opened. FILE_FLAG_OPEN_REPARSE_POINT opens the final reparse
// object itself instead of silently following it.
func openPath(path []uint16) (syscall.Handle, error) {
	if len(path) == 0 || path[len(path)-1] != 0 {
		return syscall.InvalidHandle, ErrInvalidPath
	}

	handle, err := syscall.CreateFile(
		&path[0],
		fileReadAttributes,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	return handle, nil
}

func queryFileInformation(handle syscall.Handle, class uint32, output unsafe.Pointer, size uintptr) error {
	r1, _, callErr := procGetFileInformationByHandleEx.Call(
		uintptr(handle),
		uintptr(class),
		uintptr(output),
		size,
	)
	if r1 == 0 {
		return callErr
	}
	return nil
}

// queryNativeState gets metadata and FILE_ID_INFO from the same open handle.
func queryNativeState(handle syscall.Handle) (nativeState, error) {
	var state nativeState

	if err := queryFileInformation(
		handle,
		fileBasicInfoClass,
		unsafe.Pointer(&state.Basic),
		unsafe.Sizeof(state.Basic),
	); err != nil {
		return nativeState{}, &Error{
			Stage: StageMetadata,
			Op:    "GetFileInformationByHandleEx(FileBasicInfo)",
			Err:   err,
		}
	}

	if err := queryFileInformation(
		handle,
		fileStandardInfoClass,
		unsafe.Pointer(&state.Standard),
		unsafe.Sizeof(state.Standard),
	); err != nil {
		return nativeState{}, &Error{
			Stage: StageMetadata,
			Op:    "GetFileInformationByHandleEx(FileStandardInfo)",
			Err:   err,
		}
	}

	if err := queryFileInformation(
		handle,
		fileIdInfoClass,
		unsafe.Pointer(&state.ID),
		unsafe.Sizeof(state.ID),
	); err != nil {
		return nativeState{}, &Error{
			Stage: StageIdentity,
			Op:    "GetFileInformationByHandleEx(FileIdInfo)",
			Err:   err,
		}
	}

	return state, nil
}

// queryStreams asks Windows for FILE_STREAM_INFO using a bounded growing buffer.
func queryStreams(handle syscall.Handle) ([]nativeStream, error) {
	for size := initialStreamInfoBuffer; size <= maximumStreamInfoBuffer; size *= 2 {
		buffer := make([]byte, size)

		r1, _, callErr := procGetFileInformationByHandleEx.Call(
			uintptr(handle),
			uintptr(fileStreamInfoClass),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
		)
		if r1 != 0 {
			return parseStreamInfo(buffer)
		}

		if errno, ok := callErr.(syscall.Errno); ok {
			switch errno {
			case errorInsufficientBuffer, errorMoreData:
				continue
			case errorHandleEOF:
				return []nativeStream{}, nil
			}
		}

		return nil, &Error{
			Stage: StageStreams,
			Op:    "GetFileInformationByHandleEx(FileStreamInfo)",
			Err:   callErr,
		}
	}

	return nil, &Error{
		Stage: StageStreams,
		Op:    "GetFileInformationByHandleEx(FileStreamInfo)",
		Err:   ErrStreamBufferLimit,
	}
}

// parseStreamInfo parses the chained variable-length FILE_STREAM_INFO records
// returned by Windows.
//
// NextEntryOffset must be 8-byte aligned and must start after the current
// variable-length stream name. This prevents a malformed offset from pointing
// into the current record's name payload.
func parseStreamInfo(buffer []byte) ([]nativeStream, error) {
	if len(buffer) < fileStreamInfoHeader {
		return nil, ErrMalformedStreamInfo
	}

	streams := make([]nativeStream, 0, 4)
	for offset := 0; ; {
		if offset < 0 || offset+fileStreamInfoHeader > len(buffer) {
			return nil, ErrMalformedStreamInfo
		}

		entry := buffer[offset:]
		next := int(binary.LittleEndian.Uint32(entry[0:4]))
		nameBytes := int(binary.LittleEndian.Uint32(entry[4:8]))

		if nameBytes < 0 || nameBytes%2 != 0 || fileStreamInfoHeader+nameBytes > len(entry) {
			return nil, ErrMalformedStreamInfo
		}

		name := make([]uint16, nameBytes/2)
		for i := range name {
			start := fileStreamInfoHeader + i*2
			name[i] = binary.LittleEndian.Uint16(entry[start : start+2])
		}

		streams = append(streams, nativeStream{
			Name:           name,
			Size:           int64(binary.LittleEndian.Uint64(entry[8:16])),
			AllocationSize: int64(binary.LittleEndian.Uint64(entry[16:24])),
		})

		if next == 0 {
			break
		}

		minimumNext := align8(fileStreamInfoHeader + nameBytes)
		if next < minimumNext ||
			next%8 != 0 ||
			offset+next <= offset ||
			offset+next > len(buffer) {
			return nil, ErrMalformedStreamInfo
		}

		offset += next
	}

	return streams, nil
}

func align8(value int) int {
	return (value + 7) &^ 7
}

// queryVolume returns the filesystem name for the volume containing the open
// handle. The collector accepts only NTFS.
func queryVolume(handle syscall.Handle) (string, error) {
	var fileSystemBuffer [32]uint16

	r1, _, callErr := procGetVolumeInformationByHandleW.Call(
		uintptr(handle),
		0,
		0,
		0,
		0,
		0,
		uintptr(unsafe.Pointer(&fileSystemBuffer[0])),
		uintptr(len(fileSystemBuffer)),
	)
	if r1 == 0 {
		return "", callErr
	}

	return syscall.UTF16ToString(fileSystemBuffer[:]), nil
}

// finalVolumePath resolves an open handle to a normalized volume-GUID path.
//
// FI uses this handle-derived path for containment rather than trusting the
// caller's original drive-letter string.
func finalVolumePath(handle syscall.Handle) ([]uint16, error) {
	buffer := make([]uint16, 512)

	for attempts := 0; attempts < 3; attempts++ {
		length, _, callErr := procGetFinalPathNameByHandleW.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
			fileNameNormalized|volumeNameGUID,
		)
		if length == 0 {
			return nil, callErr
		}

		if length < uintptr(len(buffer)) {
			result := append([]uint16(nil), buffer[:length]...)
			if !hasASCIIPrefix(result, `\\?\Volume{`) {
				return nil, ErrNotLocalVolume
			}
			if _, err := volumeGUIDFromFinalPath(result); err != nil {
				return nil, err
			}
			return result, nil
		}

		buffer = make([]uint16, int(length)+1)
	}

	return nil, fmt.Errorf("final path exceeded retry bound")
}

func volumeGUIDFromFinalPath(path []uint16) (string, error) {
	if !hasASCIIPrefix(path, `\\?\Volume{`) {
		return "", ErrNotLocalVolume
	}

	for index := len(`\\?\Volume{`); index+1 < len(path); index++ {
		if path[index] == '}' && path[index+1] == '\\' {
			return syscall.UTF16ToString(path[:index+2]), nil
		}
	}

	return "", fmt.Errorf("volume GUID terminator missing")
}
