// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnraw

import (
	"encoding/binary"
	"errors"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

const (
	containmentFileIDType         = 0
	containmentFileReadAttributes = 0x00000080
	containmentFileNameNormalized = 0x0000
	containmentVolumeNameGUID     = 0x0001
	containmentMaximumPathUnits   = 64 * 1024
)

const containmentWindowsErrorInvalidParameter syscall.Errno = 87

type ContainmentResult byte

const (
	ContainmentContained   ContainmentResult = 1
	ContainmentOutside     ContainmentResult = 2
	ContainmentUnavailable ContainmentResult = 3
)

type containmentFileIDDescriptor struct {
	Size       uint32
	Type       uint32
	Identifier [16]byte
}

var (
	_ [24 - unsafe.Sizeof(containmentFileIDDescriptor{})]byte
	_ [unsafe.Sizeof(containmentFileIDDescriptor{}) - 24]byte

	procContainmentGetFinalPathNameByHandleW = kernel32.NewProc("GetFinalPathNameByHandleW")
	procContainmentOpenFileByID              = kernel32.NewProc("OpenFileById")
)

// CheckContainment determines whether one exact NTFS object identity is
// currently inside governedRoot. It requests zero access for the target object
// and returns only a mechanical result. No target path, metadata, security
// descriptor, or content leaves this privileged package.
func CheckContainment(
	governedRoot string,
	fileReferenceNumber uint64,
	sequenceNumber uint16,
) (ContainmentResult, error) {
	if fileReferenceNumber >= 1<<48 {
		return 0, errors.New("file reference number exceeds 48-bit NTFS record number")
	}
	if _, err := DriveForRoot(governedRoot); err != nil {
		return 0, err
	}

	rootHandle, err := containmentOpenPath(governedRoot)
	if err != nil {
		return 0, err
	}
	defer syscall.CloseHandle(rootHandle)

	rootPath, err := containmentFinalVolumePath(rootHandle)
	if err != nil {
		return 0, err
	}

	targetHandle, err := containmentOpenFileByID(
		rootHandle,
		fileReferenceNumber,
		sequenceNumber,
	)
	if errors.Is(err, syscall.ERROR_ACCESS_DENIED) && containmentServer2022() {
		return containmentCheckServer2022(
			rootHandle,
			rootPath,
			fileReferenceNumber,
			sequenceNumber,
		)
	}
	if err != nil {
		switch {
		case errors.Is(err, syscall.ERROR_FILE_NOT_FOUND),
			errors.Is(err, syscall.ERROR_PATH_NOT_FOUND),
			errors.Is(err, containmentWindowsErrorInvalidParameter):
			return ContainmentUnavailable, nil
		default:
			return 0, err
		}
	}
	defer syscall.CloseHandle(targetHandle)

	targetPath, err := containmentFinalVolumePath(targetHandle)
	if err != nil {
		return 0, err
	}
	if containmentPathContainedBy(rootPath, targetPath) {
		return ContainmentContained, nil
	}
	return ContainmentOutside, nil
}

func containmentFinalVolumePath(handle syscall.Handle) (string, error) {
	buffer := make([]uint16, 512)
	for attempts := 0; attempts < 3; attempts++ {
		length, _, callErr := procContainmentGetFinalPathNameByHandleW.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
			containmentFileNameNormalized|containmentVolumeNameGUID,
		)
		if length == 0 {
			return "", callErr
		}
		if length < uintptr(len(buffer)) {
			return syscall.UTF16ToString(buffer[:length]), nil
		}
		if length >= uintptr(containmentMaximumPathUnits) {
			return "", errors.New("final path exceeds bounded UTF-16 limit")
		}
		buffer = make([]uint16, int(length)+1)
	}
	return "", errors.New("final path exceeded retry bound")
}

func containmentOpenFileByID(
	volumeHint syscall.Handle,
	fileReferenceNumber uint64,
	sequenceNumber uint16,
) (syscall.Handle, error) {
	fileID := fileReferenceNumber | uint64(sequenceNumber)<<48
	descriptor := containmentFileIDDescriptor{
		Size: uint32(unsafe.Sizeof(containmentFileIDDescriptor{})),
		Type: containmentFileIDType,
	}
	binary.LittleEndian.PutUint64(descriptor.Identifier[:8], fileID)

	r1, _, callErr := procContainmentOpenFileByID.Call(
		uintptr(volumeHint),
		uintptr(unsafe.Pointer(&descriptor)),
		0,
		uintptr(syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE),
		0,
		uintptr(syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT),
	)
	runtime.KeepAlive(&descriptor)

	handle := syscall.Handle(r1)
	if handle == syscall.InvalidHandle {
		return syscall.InvalidHandle, callErr
	}
	return handle, nil
}

func containmentOpenPath(path string) (syscall.Handle, error) {
	units, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return syscall.InvalidHandle, err
	}
	return syscall.CreateFile(
		units,
		containmentFileReadAttributes,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
}

func containmentPathContainedBy(root, target string) bool {
	root = strings.TrimRight(root, `\`)
	target = strings.TrimRight(target, `\`)
	if root == "" || target == "" {
		return false
	}

	root = strings.ToLower(root)
	target = strings.ToLower(target)
	if target == root {
		return true
	}
	return len(target) > len(root) &&
		strings.HasPrefix(target, root) &&
		target[len(root)] == '\\'
}
