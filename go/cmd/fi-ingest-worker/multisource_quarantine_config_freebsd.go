// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

func m1PathWithin(parent, path string) bool {
	rel, err := filepath.Rel(parent, path)
	if err != nil {
		return false
	}

	return rel == "." ||
		(rel != ".." &&
			!strings.HasPrefix(
				rel, ".."+string(filepath.Separator),
			) &&
			!filepath.IsAbs(rel))
}

// m1ValidateQuarantineConfiguration checks static configuration.
// Filesystem ownership, symlinks, permissions, and marker integrity
// are validated separately by the durable store during startup.
//
// This function never creates directories or modifies a service.
func m1ValidateQuarantineConfiguration(
	config workerConfig,
) error {
	root := config.QuarantineRoot

	if !config.SourceNamespaces {
		if root != "" {
			return errors.New(
				"FI quarantine root requires source namespaces",
			)
		}
		return nil
	}

	if root == "" ||
		!filepath.IsAbs(root) ||
		filepath.Clean(root) != root ||
		root == string(filepath.Separator) {
		return errors.New(
			"FI namespaced ingest requires a clean absolute quarantine root",
		)
	}

	for _, ephemeral := range []string{
		"/tmp",
		"/var/tmp",
		"/run",
		"/var/run",
		"/dev",
	} {
		if m1PathWithin(ephemeral, root) {
			return fmt.Errorf(
				"FI quarantine root %q is in nonpersistent or unsuitable storage %q",
				root, ephemeral,
			)
		}
	}

	protected := []struct {
		name string
		path string
	}{
		{"custody", config.CustodyRoot},
		{"recorded", config.RecordedRoot},
		{"ready", config.ReadyRoot},
	}

	for _, item := range protected {
		if item.path == "" {
			continue
		}

		if !filepath.IsAbs(item.path) ||
			filepath.Clean(item.path) != item.path {
			return fmt.Errorf(
				"FI %s root must be a clean absolute path",
				item.name,
			)
		}

		if m1PathWithin(root, item.path) ||
			m1PathWithin(item.path, root) {
			return fmt.Errorf(
				"FI quarantine root overlaps %s storage",
				item.name,
			)
		}
	}

	if config.LockFile != "" {
		if !filepath.IsAbs(config.LockFile) ||
			filepath.Clean(config.LockFile) != config.LockFile {
			return errors.New(
				"FI worker lock path must be a clean absolute path",
			)
		}

		if m1PathWithin(root, config.LockFile) {
			return errors.New(
				"FI worker lock must not reside in quarantine state",
			)
		}
	}

	return nil
}
