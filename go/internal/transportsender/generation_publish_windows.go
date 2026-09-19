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

const generationMoveFileWriteThrough = 0x00000008

var generationMoveFileExW = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

func publishGenerationDirectory(source, destination string) error {
	sourcePtr, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	destinationPtr, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	result, _, callErr := generationMoveFileExW.Call(
		uintptr(unsafe.Pointer(sourcePtr)),
		uintptr(unsafe.Pointer(destinationPtr)),
		uintptr(generationMoveFileWriteThrough),
	)
	if result == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return callErr
		}
		return errors.New("MoveFileExW failed publishing FI generation directory")
	}
	return nil
}
