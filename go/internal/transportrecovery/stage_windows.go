// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package transportrecovery

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const recoveryMoveFileWriteThrough = 0x00000008

var recoveryMoveFileExW = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

func publishRecoveryFrame(source, destination string) (bool, error) {
	sourcePtr, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return false, err
	}
	destinationPtr, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return false, err
	}
	result, _, callErr := recoveryMoveFileExW.Call(
		uintptr(unsafe.Pointer(sourcePtr)),
		uintptr(unsafe.Pointer(destinationPtr)),
		uintptr(recoveryMoveFileWriteThrough),
	)
	if result != 0 {
		return true, nil
	}
	if errno, ok := callErr.(syscall.Errno); ok && (errno == syscall.Errno(80) || errno == syscall.Errno(183)) {
		return false, nil
	}
	if callErr != nil && callErr != syscall.Errno(0) {
		return false, callErr
	}
	return false, errors.New("MoveFileExW failed for FI recovery publication")
}

func removeRecoveryFrame(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		_ = os.Chmod(path, 0o400)
		return err
	}
	return nil
}

func validateRecoveryStageDirectoryPath(path string) error {
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	if volume == "" {
		return errors.New("FI recovery stage directory volume is required")
	}
	root := volume + string(filepath.Separator)
	relative, err := filepath.Rel(root, clean)
	if err != nil {
		return fmt.Errorf("resolve FI recovery stage directory relative path: %w", err)
	}
	if relative == "." {
		return nil
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("FI recovery stage directory escaped its Windows volume root")
	}
	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, component)
		nativePath, err := syscall.UTF16PtrFromString(current)
		if err != nil {
			return fmt.Errorf("encode FI recovery stage directory component %q: %w", current, err)
		}
		attributes, err := syscall.GetFileAttributes(nativePath)
		if err != nil {
			return fmt.Errorf("inspect FI recovery stage directory component %q: %w", current, err)
		}
		if attributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("FI recovery stage directory path must not traverse Windows reparse points")
		}
	}
	return nil
}
