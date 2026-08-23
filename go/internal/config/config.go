// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package config

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

const Version1 = "1.0"

// Config is the complete FI configuration understood by this parser version.
// Collection behavior remains defined by FI code. The configuration only
// defines the governed roots on which FI is allowed to operate.
type Config struct {
	VersionID     string
	GovernedRoots []string
}

// Load reads and validates one FI configuration file.
func Load(path string) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open FI config: %w", err)
	}
	defer file.Close()

	value, err := Parse(file)
	if err != nil {
		return Config{}, fmt.Errorf("parse FI config %q: %w", path, err)
	}
	return value, nil
}

// Parse reads FI configuration version 1.0.
//
// The first meaningful line must be:
//
//	version_id: 1.0
//
// Each remaining meaningful line must be:
//
//	governed_root: D:\\Shares\\Finance
//
// Blank lines and full-line comments beginning with # are ignored.
func Parse(reader io.Reader) (Config, error) {
	if reader == nil {
		return Config{}, errors.New("reader is required")
	}

	scanner := bufio.NewScanner(reader)
	// A governed-root line should always be tiny, but use a bounded larger
	// buffer so an unusual yet valid Windows path is not limited by Scanner's
	// default token size.
	scanner.Buffer(make([]byte, 4096), 1024*1024)

	var value Config
	seenVersion := false
	seenRoots := make(map[string]struct{})
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if lineNumber == 1 {
			line = strings.TrimPrefix(line, "\uFEFF")
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, rawValue, ok := strings.Cut(line, ":")
		if !ok {
			return Config{}, fmt.Errorf("line %d: expected directive followed by ':'", lineNumber)
		}
		key = strings.TrimSpace(key)
		rawValue = strings.TrimSpace(rawValue)

		if !seenVersion {
			if key != "version_id" {
				return Config{}, fmt.Errorf("line %d: first directive must be version_id", lineNumber)
			}
			if rawValue != Version1 {
				return Config{}, fmt.Errorf("line %d: unsupported version_id %q", lineNumber, rawValue)
			}
			value.VersionID = rawValue
			seenVersion = true
			continue
		}

		switch key {
		case "version_id":
			return Config{}, fmt.Errorf("line %d: duplicate version_id", lineNumber)
		case "governed_root":
			if rawValue == "" {
				return Config{}, fmt.Errorf("line %d: governed_root path is required", lineNumber)
			}
			if err := validateGovernedRoot(rawValue); err != nil {
				return Config{}, fmt.Errorf("line %d: governed_root: %w", lineNumber, err)
			}

			rootKey := governedRootKey(rawValue)
			if _, exists := seenRoots[rootKey]; exists {
				return Config{}, fmt.Errorf("line %d: duplicate governed_root %q", lineNumber, rawValue)
			}
			seenRoots[rootKey] = struct{}{}
			value.GovernedRoots = append(value.GovernedRoots, rawValue)
		default:
			return Config{}, fmt.Errorf("line %d: unknown directive %q", lineNumber, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	if !seenVersion {
		return Config{}, errors.New("version_id is required")
	}
	if len(value.GovernedRoots) == 0 {
		return Config{}, errors.New("at least one governed_root is required")
	}
	return value, nil
}

func validateGovernedRoot(path string) error {
	if !utf8.ValidString(path) {
		return errors.New("path is not valid UTF-8")
	}
	if len(path) < 3 {
		return errors.New("path must be an absolute local Windows path")
	}
	if !isASCIILetter(path[0]) || path[1] != ':' || path[2] != '\\' {
		return errors.New("path must be an absolute local Windows path such as D:\\Shares\\Finance")
	}
	if strings.Contains(path, "/") {
		return errors.New("path must use Windows backslashes")
	}
	if strings.ContainsRune(path[3:], ':') {
		return errors.New("path contains an unexpected ':'")
	}

	for _, part := range strings.Split(path[3:], "\\") {
		switch part {
		case ".", "..":
			return errors.New("path must not contain '.' or '..' segments")
		}
	}
	return nil
}

func governedRootKey(path string) string {
	key := strings.TrimRight(path, "\\")
	if len(key) == 2 && key[1] == ':' {
		key += "\\"
	}
	return strings.ToLower(key)
}

func isASCIILetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}
