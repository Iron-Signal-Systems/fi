// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const defaultFileName = "fi.conf"

// DefaultPath returns the fixed Phase 1 FI configuration path.
func DefaultPath() (string, error) {
	programData := strings.TrimSpace(os.Getenv("ProgramData"))
	if programData == "" {
		return "", errors.New("ProgramData is not set")
	}
	return filepath.Join(programData, "FI", "config", defaultFileName), nil
}

// LoadDefault reads and validates the fixed Phase 1 FI configuration file.
func LoadDefault() (Config, string, error) {
	path, err := DefaultPath()
	if err != nil {
		return Config{}, "", err
	}
	value, err := Load(path)
	if err != nil {
		return Config{}, path, err
	}
	return value, path, nil
}
