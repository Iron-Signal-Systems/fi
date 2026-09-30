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
)

// ValidateGovernedRootsForInstall validates operator-owned collection roots.
// FI may validate these paths, but it must not manufacture customer data scope.
func ValidateGovernedRootsForInstall(roots []string) error {
	for _, raw := range roots {
		root := strings.TrimSpace(raw)
		if root == "" {
			return fmt.Errorf("governed root is empty")
		}
		if !filepath.IsAbs(root) {
			return fmt.Errorf(
				"governed root must be an absolute Windows path: %q",
				raw,
			)
		}

		info, err := os.Stat(root)
		if err != nil {
			if os.IsNotExist(err) {
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
		if !info.IsDir() {
			return fmt.Errorf(
				"governed root %q is not a directory",
				root,
			)
		}
	}
	return nil
}
