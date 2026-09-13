// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package transportsender

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
)

func validateOutboundStageDirectoryPath(path string) error {
	clean := filepath.Clean(path)
	volume := filepath.VolumeName(clean)
	if volume == "" {
		return errors.New("FI outbound stage directory volume is required")
	}

	root := volume + string(filepath.Separator)
	relative, err := filepath.Rel(root, clean)
	if err != nil {
		return fmt.Errorf(
			"resolve FI outbound stage directory relative path: %w",
			err,
		)
	}
	if relative == "." {
		return nil
	}
	if relative == ".." ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New(
			"FI outbound stage directory escaped its Windows volume root",
		)
	}

	current := root
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}

		current = filepath.Join(current, component)
		nativePath, err := syscall.UTF16PtrFromString(current)
		if err != nil {
			return fmt.Errorf(
				"encode FI outbound stage directory component %q: %w",
				current,
				err,
			)
		}

		attributes, err := syscall.GetFileAttributes(nativePath)
		if err != nil {
			return fmt.Errorf(
				"inspect FI outbound stage directory component %q: %w",
				current,
				err,
			)
		}
		if attributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New(
				"FI outbound stage directory path must not traverse Windows reparse points",
			)
		}
	}

	return nil
}
