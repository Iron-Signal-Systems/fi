// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package runtimeidentity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Executable identifies the exact executable file from which the current FI
// process was started. SHA256 is lowercase hexadecimal.
type Executable struct {
	Path   string
	SHA256 string
}

var (
	currentExecutableOnce sync.Once
	currentExecutable     Executable
	currentExecutableErr  error
)

// CurrentExecutable returns the current executable path and SHA-256. The file is
// hashed once per process and the result is cached for all later callers.
func CurrentExecutable() (Executable, error) {
	currentExecutableOnce.Do(func() {
		currentExecutable, currentExecutableErr = readCurrentExecutable()
	})
	return currentExecutable, currentExecutableErr
}

func readCurrentExecutable() (Executable, error) {
	path, err := os.Executable()
	if err != nil {
		return Executable{}, fmt.Errorf("locate current executable: %w", err)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return Executable{}, fmt.Errorf("resolve current executable path: %w", err)
	}
	path = filepath.Clean(path)

	file, err := os.Open(path)
	if err != nil {
		return Executable{}, fmt.Errorf("open current executable: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return Executable{}, fmt.Errorf("hash current executable: %w", err)
	}

	return Executable{
		Path:   path,
		SHA256: hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}
