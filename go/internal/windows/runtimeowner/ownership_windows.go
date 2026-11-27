// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package runtimeowner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const DefaultLockFileName = "collector-runtime.lock"

var ErrAlreadyHeld = errors.New("FI collector runtime ownership is already held")

// Ownership is the exclusive host-local collector runtime handle.
//
// The lock file is intentionally persistent. Ownership is represented by the
// open Windows file handle with share mode zero, not by file existence. Process
// termination closes the handle automatically, so a stale lock file after a
// crash does not block a later collector start.
type Ownership struct {
	path   string
	handle syscall.Handle
	closed bool
}

func DefaultPath() (string, error) {
	base := os.Getenv("FI_STATE_DIR")
	if base == "" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			return "", errors.New("ProgramData is not set")
		}
		base = filepath.Join(programData, "FI", "state")
	}
	return filepath.Join(base, DefaultLockFileName), nil
}

func Acquire() (*Ownership, error) {
	path, err := DefaultPath()
	if err != nil {
		return nil, err
	}
	return AcquirePath(path)
}

func AcquirePath(path string) (*Ownership, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("runtime ownership path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create runtime ownership directory: %w", err)
	}

	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	handle, err := syscall.CreateFile(
		pathPtr,
		syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		0,
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		// ERROR_SHARING_VIOLATION = 32. The syscall package does not expose a
		// named constant for it on all supported Go versions.
		if errors.Is(err, syscall.Errno(32)) {
			return nil, fmt.Errorf("%w: %s", ErrAlreadyHeld, path)
		}
		return nil, fmt.Errorf("open runtime ownership file %q: %w", path, err)
	}

	return &Ownership{
		path:   path,
		handle: handle,
	}, nil
}

func (ownership *Ownership) Close() error {
	if ownership == nil || ownership.closed {
		return nil
	}
	ownership.closed = true

	if err := syscall.CloseHandle(ownership.handle); err != nil {
		return fmt.Errorf(
			"close runtime ownership file %q: %w",
			ownership.path,
			err,
		)
	}
	return nil
}

func (ownership *Ownership) Path() string {
	if ownership == nil {
		return ""
	}
	return ownership.path
}
