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

func removeOutboundFrame(path string) (bool, error) {
	// The staged frame is intentionally read-only. Windows treats that attribute
	// as a deletion barrier, so make it writable only for the final authorized
	// cleanup attempt and restore read-only state if deletion fails.
	if err := os.Chmod(path, 0o600); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}

	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}

		restoreErr := os.Chmod(path, 0o400)
		if restoreErr != nil && !errors.Is(restoreErr, fs.ErrNotExist) {
			return false, errors.Join(err, restoreErr)
		}
		return false, err
	}

	return true, nil
}
