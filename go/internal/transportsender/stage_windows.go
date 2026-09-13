// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package transportsender

import (
	"errors"
	"syscall"
	"unsafe"
)

const outboundMoveFileWriteThrough = 0x00000008

var outboundMoveFileExW = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

func publishOutboundFrame(source string, destination string) (bool, error) {
	sourcePtr, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return false, err
	}
	destinationPtr, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return false, err
	}

	result, _, callErr := outboundMoveFileExW.Call(
		uintptr(unsafe.Pointer(sourcePtr)),
		uintptr(unsafe.Pointer(destinationPtr)),
		uintptr(outboundMoveFileWriteThrough),
	)
	if result != 0 {
		return true, nil
	}

	if errno, ok := callErr.(syscall.Errno); ok {
		// ERROR_FILE_EXISTS (80) and ERROR_ALREADY_EXISTS (183) both mean
		// another preparer already published the no-replace destination.
		if errno == syscall.Errno(80) || errno == syscall.Errno(183) {
			return false, nil
		}
	}
	if callErr != nil && callErr != syscall.Errno(0) {
		return false, callErr
	}
	return false, errors.New("MoveFileExW failed for FI outbound publication")
}
