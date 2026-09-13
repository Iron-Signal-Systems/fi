// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build !windows

package transportsender

import (
	"errors"
	"fmt"
	"path/filepath"
)

func validateOutboundStageDirectoryPath(path string) error {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("resolve FI outbound stage directory: %w", err)
	}
	if filepath.Clean(resolved) != filepath.Clean(path) {
		return errors.New(
			"FI outbound stage directory path must not traverse symlinks",
		)
	}
	return nil
}
