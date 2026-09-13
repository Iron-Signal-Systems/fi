// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux || darwin

package transportsender

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

func publishOutboundFrame(source string, destination string) (bool, error) {
	if filepath.Dir(source) != filepath.Dir(destination) {
		return false, errors.New("FI outbound publication requires one directory")
	}
	if err := os.Link(source, destination); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, nil
		}
		return false, err
	}
	if err := os.Remove(source); err != nil {
		_ = os.Remove(destination)
		return false, err
	}
	if err := syncOutboundDirectory(filepath.Dir(destination)); err != nil {
		return false, err
	}
	return true, nil
}

func syncOutboundDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}
