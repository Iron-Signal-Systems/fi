// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package transportsender

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"unsafe"
)

func removeOutboundFrame(path string) (bool, error) {
	// The staged frame is intentionally read-only. Windows treats that attribute
	// as a deletion barrier, so make it writable only for the final authorized
	// cleanup attempt and restore read-only state if deletion fails.
	if err := os.Chmod(path, 0o600); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}

	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		_ = os.Chmod(path, 0o400)
		return false, err
	}

	result, _, callErr := outboundMoveFileExW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		uintptr(outboundMoveFileWriteThrough),
	)
	if result != 0 {
		return true, nil
	}

	if errno, ok := callErr.(syscall.Errno); ok {
		if errno == syscall.Errno(2) || errno == syscall.Errno(3) {
			return false, nil
		}
	}

	restoreErr := os.Chmod(path, 0o400)
	if callErr != nil && callErr != syscall.Errno(0) {
		if restoreErr != nil {
			return false, errors.Join(callErr, restoreErr)
		}
		return false, callErr
	}
	if restoreErr != nil {
		return false, errors.Join(
			errors.New("MoveFileExW failed for FI outbound cleanup"),
			restoreErr,
		)
	}
	return false, errors.New("MoveFileExW failed for FI outbound cleanup")
}
