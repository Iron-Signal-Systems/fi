// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package transportsender

import (
	"errors"
	"io/fs"
	"os"
)

func removeGenerationReclamationPath(path string) (bool, error) {
	if err := os.RemoveAll(path); err != nil {
		return false, err
	}
	if _, err := os.Lstat(path); err == nil {
		return false, errors.New("FI generation reclamation path still exists after removal")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return false, err
	}
	return true, nil
}
