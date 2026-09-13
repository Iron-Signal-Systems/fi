// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build !windows

package transportsender

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

func removeOutboundFrame(path string) (bool, error) {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}

	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return true, err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return true, err
	}
	if err := directory.Close(); err != nil {
		return true, err
	}
	return true, nil
}
