// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/sys/windows"
)

// ValidateGovernedRootsForInstall validates operator-owned collection roots.
// FI may validate these paths, but it must not manufacture customer data scope.
//
// The installer rejects a configured root that is itself a reparse point.
// The collection engine independently re-proves the governed-root handle,
// NTFS volume, object identity, non-reparse state, and containment at runtime.
func ValidateGovernedRootsForInstall(
	roots []string,
) error {
	seen := make(
		map[string]struct{},
		len(roots),
	)

	for _, raw := range roots {
		root := strings.TrimSpace(
			raw,
		)

		if err := validateGovernedRootInstallPath(
			root,
		); err != nil {
			return err
		}

		key := strings.ToLower(
			filepath.Clean(
				root,
			),
		)
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf(
				"governed root %q is duplicated",
				root,
			)
		}
		seen[key] = struct{}{}

		name, err := windows.UTF16PtrFromString(
			root,
		)
		if err != nil {
			return fmt.Errorf(
				"encode governed root %q: %w",
				root,
				err,
			)
		}

		attributes, err := windows.GetFileAttributes(
			name,
		)
		if err != nil {
			if os.IsNotExist(
				err,
			) {
				return fmt.Errorf(
					"governed root %q does not exist; FI does not create operator-owned collection roots",
					root,
				)
			}

			return fmt.Errorf(
				"inspect governed root %q: %w",
				root,
				err,
			)
		}

		if err := validateGovernedRootAttributes(
			root,
			attributes,
		); err != nil {
			return err
		}
	}

	return nil
}

func validateGovernedRootAttributes(
	root string,
	attributes uint32,
) error {
	if attributes&
		windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf(
			"governed root %q is a reparse point; FI requires the configured governed root itself to be a plain directory",
			root,
		)
	}

	if attributes&
		windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return fmt.Errorf(
			"governed root %q is not a directory",
			root,
		)
	}

	return nil
}

func validateGovernedRootInstallPath(
	root string,
) error {
	if root == "" {
		return fmt.Errorf(
			"governed root is empty",
		)
	}

	if !utf8.ValidString(
		root,
	) {
		return fmt.Errorf(
			"governed root path is not valid UTF-8",
		)
	}

	if len(root) < 3 ||
		!isGovernedRootDriveLetter(
			root[0],
		) ||
		root[1] != ':' ||
		root[2] != '\\' {
		return fmt.Errorf(
			"governed root must be an absolute local Windows path such as D:\\Shares\\Finance: %q",
			root,
		)
	}

	if strings.Contains(
		root,
		"/",
	) {
		return fmt.Errorf(
			"governed root must use Windows backslashes: %q",
			root,
		)
	}

	if strings.ContainsRune(
		root[3:],
		':',
	) {
		return fmt.Errorf(
			"governed root contains an unexpected ':': %q",
			root,
		)
	}

	for _, part := range strings.Split(
		root[3:],
		`\`,
	) {
		switch part {
		case ".", "..":
			return fmt.Errorf(
				"governed root must not contain '.' or '..' segments: %q",
				root,
			)
		}
	}

	return nil
}

func isGovernedRootDriveLetter(
	value byte,
) bool {
	return value >= 'A' &&
		value <= 'Z' ||
		value >= 'a' &&
			value <= 'z'
}
