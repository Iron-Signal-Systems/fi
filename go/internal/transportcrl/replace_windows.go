// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package transportcrl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32ReplaceFile = windows.NewLazySystemDLL(
		"kernel32.dll",
	)

	procReplaceFileW = kernel32ReplaceFile.NewProc(
		"ReplaceFileW",
	)
)

func ReplaceExistingFileWithBackup(
	replacedPath string,
	replacementPath string,
	backupPath string,
) error {
	replacedPath, err :=
		normalizeReplacementPath(
			"replaced",
			replacedPath,
		)
	if err != nil {
		return err
	}

	replacementPath, err =
		normalizeReplacementPath(
			"replacement",
			replacementPath,
		)
	if err != nil {
		return err
	}

	backupPath, err =
		normalizeReplacementPath(
			"backup",
			backupPath,
		)
	if err != nil {
		return err
	}

	if pathsEqualFold(
		replacedPath,
		replacementPath,
	) {
		return errors.New(
			"replaced and replacement paths must differ",
		)
	}

	if pathsEqualFold(
		replacedPath,
		backupPath,
	) {
		return errors.New(
			"replaced and backup paths must differ",
		)
	}

	if pathsEqualFold(
		replacementPath,
		backupPath,
	) {
		return errors.New(
			"replacement and backup paths must differ",
		)
	}

	replacedDirectory :=
		filepath.Dir(
			replacedPath,
		)

	if !pathsEqualFold(
		replacedDirectory,
		filepath.Dir(
			replacementPath,
		),
	) ||
		!pathsEqualFold(
			replacedDirectory,
			filepath.Dir(
				backupPath,
			),
		) {
		return errors.New(
			"replaced, replacement, and backup files must reside in the same directory",
		)
	}

	if err := requireRegularReplacementFile(
		"replaced",
		replacedPath,
	); err != nil {
		return err
	}

	if err := requireRegularReplacementFile(
		"replacement",
		replacementPath,
	); err != nil {
		return err
	}

	if _, err := os.Lstat(
		backupPath,
	); err == nil {
		return fmt.Errorf(
			"backup path already exists: %s",
			backupPath,
		)
	} else if !errors.Is(
		err,
		os.ErrNotExist,
	) {
		return fmt.Errorf(
			"inspect backup path %s: %w",
			backupPath,
			err,
		)
	}

	replacement, err := os.OpenFile(
		replacementPath,
		os.O_RDWR,
		0,
	)
	if err != nil {
		return fmt.Errorf(
			"open replacement file %s for flush: %w",
			replacementPath,
			err,
		)
	}

	if err := replacement.Sync(); err != nil {
		_ = replacement.Close()

		return fmt.Errorf(
			"flush replacement file %s: %w",
			replacementPath,
			err,
		)
	}

	if err := replacement.Close(); err != nil {
		return fmt.Errorf(
			"close replacement file %s after flush: %w",
			replacementPath,
			err,
		)
	}

	replacedUTF16, err :=
		windows.UTF16PtrFromString(
			replacedPath,
		)
	if err != nil {
		return fmt.Errorf(
			"encode replaced path: %w",
			err,
		)
	}

	replacementUTF16, err :=
		windows.UTF16PtrFromString(
			replacementPath,
		)
	if err != nil {
		return fmt.Errorf(
			"encode replacement path: %w",
			err,
		)
	}

	backupUTF16, err :=
		windows.UTF16PtrFromString(
			backupPath,
		)
	if err != nil {
		return fmt.Errorf(
			"encode backup path: %w",
			err,
		)
	}

	result, _, callErr :=
		procReplaceFileW.Call(
			uintptr(
				unsafe.Pointer(
					replacedUTF16,
				),
			),
			uintptr(
				unsafe.Pointer(
					replacementUTF16,
				),
			),
			uintptr(
				unsafe.Pointer(
					backupUTF16,
				),
			),
			0,
			0,
			0,
		)

	if result == 0 {
		return fmt.Errorf(
			"ReplaceFileW replaced=%s replacement=%s backup=%s: %w",
			replacedPath,
			replacementPath,
			backupPath,
			callErr,
		)
	}

	return nil
}

func normalizeReplacementPath(
	name string,
	path string,
) (string, error) {
	path = strings.TrimSpace(
		path,
	)

	if path == "" {
		return "", fmt.Errorf(
			"%s path is required",
			name,
		)
	}

	absolute, err :=
		filepath.Abs(
			path,
		)
	if err != nil {
		return "", fmt.Errorf(
			"resolve %s path %q: %w",
			name,
			path,
			err,
		)
	}

	return filepath.Clean(
		absolute,
	), nil
}

func pathsEqualFold(
	left string,
	right string,
) bool {
	return strings.EqualFold(
		filepath.Clean(
			left,
		),
		filepath.Clean(
			right,
		),
	)
}

func requireRegularReplacementFile(
	name string,
	path string,
) error {
	info, err := os.Lstat(
		path,
	)
	if err != nil {
		return fmt.Errorf(
			"inspect %s file %s: %w",
			name,
			path,
			err,
		)
	}

	if info.Mode()&
		os.ModeSymlink != 0 {
		return fmt.Errorf(
			"%s file %s must not be a symbolic link",
			name,
			path,
		)
	}

	if !info.Mode().
		IsRegular() {
		return fmt.Errorf(
			"%s file %s is not a regular file",
			name,
			path,
		)
	}

	return nil
}
