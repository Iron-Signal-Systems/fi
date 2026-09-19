// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package transportgeneration

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func publishGenerationPayload(
	provisionalPath string,
	finalPath string,
) error {
	return moveGenerationPathWriteThrough(
		provisionalPath,
		finalPath,
		"sealed-generation payload",
	)
}

func publishGenerationDirectory(
	provisionalPath string,
	finalPath string,
) error {
	return moveGenerationPathWriteThrough(
		provisionalPath,
		finalPath,
		"sealed-generation directory",
	)
}

func moveGenerationPathWriteThrough(
	provisionalPath string,
	finalPath string,
	objectName string,
) error {
	provisionalExtended, err :=
		extendedGenerationWindowsPath(
			provisionalPath,
		)
	if err != nil {
		return fmt.Errorf(
			"resolve %s source path: %w",
			objectName,
			err,
		)
	}

	finalExtended, err :=
		extendedGenerationWindowsPath(
			finalPath,
		)
	if err != nil {
		return fmt.Errorf(
			"resolve %s destination path: %w",
			objectName,
			err,
		)
	}

	provisional, err :=
		windows.UTF16PtrFromString(
			provisionalExtended,
		)
	if err != nil {
		return err
	}

	final, err :=
		windows.UTF16PtrFromString(
			finalExtended,
		)
	if err != nil {
		return err
	}

	if err :=
		windows.MoveFileEx(
			provisional,
			final,
			windows.MOVEFILE_WRITE_THROUGH,
		); err != nil {
		return fmt.Errorf(
			"MoveFileExW %s: %w",
			objectName,
			err,
		)
	}

	return nil
}

func extendedGenerationWindowsPath(
	path string,
) (
	string,
	error,
) {
	absolute, err :=
		filepath.Abs(
			path,
		)
	if err != nil {
		return "",
			err
	}

	if strings.HasPrefix(
		absolute,
		`\\?\`,
	) {
		return absolute, nil
	}

	if strings.HasPrefix(
		absolute,
		`\\`,
	) {
		return `\\?\UNC\` +
				strings.TrimPrefix(
					absolute,
					`\\`,
				),
			nil
	}

	return `\\?\` +
			absolute,
		nil
}
