// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build !windows

package transportsender

import (
	"fmt"
	"os"
	"path/filepath"
)

func publishGenerationDirectory(source, destination string) error {
	if err := os.Rename(source, destination); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return fmt.Errorf("open FI generation parent directory for sync: %w", err)
	}
	defer parent.Close()
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("sync FI generation parent directory: %w", err)
	}
	return nil
}
