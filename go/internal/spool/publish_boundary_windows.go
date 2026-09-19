// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package spool

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const publishBoundaryLockFileExclusive = 0x00000002
const publishBoundaryLockName = "spool-publish-boundary.lock"

var publishBoundaryKernel32 = syscall.NewLazyDLL("kernel32.dll")
var publishBoundaryLockFileEx = publishBoundaryKernel32.NewProc("LockFileEx")
var publishBoundaryUnlockFileEx = publishBoundaryKernel32.NewProc("UnlockFileEx")

type windowsPublishBoundaryGuard struct {
	file       *os.File
	overlapped syscall.Overlapped
}

// AcquirePublishBoundary obtains the machine-local FI spool publication guard.
// The guard uses a Windows byte-range file lock rather than a named mutex so it
// is process-safe and is not tied to the OS thread on which a Go goroutine ran.
// Collector writers hold it only while publishing one already-completed batch.
// Generation rollover obtains the same guard before replacing the active spool
// directory, so publication lands wholly before or after a rollover boundary.
func AcquirePublishBoundary() (io.Closer, error) {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		return nil, errors.New("ProgramData is not set")
	}
	stateDir := filepath.Join(programData, "FI", "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create FI spool publish-boundary state directory: %w", err)
	}
	path := filepath.Join(stateDir, publishBoundaryLockName)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open FI spool publish-boundary lock: %w", err)
	}
	guard := &windowsPublishBoundaryGuard{file: file}
	result, _, callErr := publishBoundaryLockFileEx.Call(
		file.Fd(),
		uintptr(publishBoundaryLockFileExclusive),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&guard.overlapped)),
	)
	if result == 0 {
		_ = file.Close()
		if callErr != nil && callErr != syscall.Errno(0) {
			return nil, fmt.Errorf("lock FI spool publish boundary: %w", callErr)
		}
		return nil, errors.New("LockFileEx failed for FI spool publish boundary")
	}
	return guard, nil
}

func (guard *windowsPublishBoundaryGuard) Close() error {
	if guard == nil || guard.file == nil {
		return nil
	}
	result, _, callErr := publishBoundaryUnlockFileEx.Call(
		guard.file.Fd(),
		0,
		1,
		0,
		uintptr(unsafe.Pointer(&guard.overlapped)),
	)
	var unlockErr error
	if result == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			unlockErr = fmt.Errorf("unlock FI spool publish boundary: %w", callErr)
		} else {
			unlockErr = errors.New("UnlockFileEx failed for FI spool publish boundary")
		}
	}
	closeErr := guard.file.Close()
	guard.file = nil
	return errors.Join(unlockErr, closeErr)
}
