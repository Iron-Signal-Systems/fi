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

const (
	defaultFileName           = "fi.conf"
	defaultTransportTrustName = "fi-transport-trust.conf"
)

// DefaultPath returns the fixed FI operational configuration path.
func DefaultPath() (string, error) {
	programData := strings.TrimSpace(os.Getenv("ProgramData"))
	if programData == "" {
		return "", errors.New("ProgramData is not set")
	}
	return filepath.Join(programData, "FI", "config", defaultFileName), nil
}

// DefaultTransportTrustPath returns the fixed FI transport-trust path.
func DefaultTransportTrustPath() (string, error) {
	programData := strings.TrimSpace(os.Getenv("ProgramData"))
	if programData == "" {
		return "", errors.New("ProgramData is not set")
	}
	return filepath.Join(programData, "FI", "config", defaultTransportTrustName), nil
}

// LoadDefault reads and validates the fixed FI operational configuration.
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

// LoadDefaultTransportTrust reads and validates the fixed transport-trust file.
func LoadDefaultTransportTrust() (TransportTrustConfig, string, error) {
	path, err := DefaultTransportTrustPath()
	if err != nil {
		return TransportTrustConfig{}, "", err
	}
	value, err := LoadTransportTrust(path)
	if err != nil {
		return TransportTrustConfig{}, path, err
	}
	return value, path, nil
}
