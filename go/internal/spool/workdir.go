// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const collectorWorkDirectoryPrefix = ".fi-"

const collectorWorkDirectorySuffix = "-collector-work"

// PhysicalSpoolDir resolves the configured FI spool path to the physical
// directory that contains published batch artifacts.
//
// This is required when the configured spool is a junction or other supported
// indirection. Operations that rename the active spool directory itself must
// operate on this physical path rather than on the configured reparse point.
// PhysicalSpoolPath resolves the configured FI spool name to the physical path
// that owns the active spool namespace.
//
// Unlike PhysicalSpoolDir, this function does not require the physical target
// directory to exist. That distinction is required to recover the narrow
// rollover crash window after the old active spool has been frozen but before
// the replacement directory has been promoted.
func PhysicalSpoolPath(
	spoolDir string,
) (
	string,
	error,
) {
	if spoolDir == "" ||
		!filepath.IsAbs(spoolDir) {
		return "", errors.New(
			"FI spool directory must be absolute",
		)
	}

	resolved, err :=
		resolveDirectoryIdentityPath(
			filepath.Clean(
				spoolDir,
			),
		)
	if err != nil {
		return "", fmt.Errorf(
			"resolve physical FI spool path: %w",
			err,
		)
	}

	if !filepath.IsAbs(
		resolved,
	) {
		return "", errors.New(
			"physical FI spool path must be absolute",
		)
	}

	return filepath.Clean(
		resolved,
	), nil
}

// PhysicalSpoolDir resolves and validates the currently existing physical FI
// active-spool directory.
func PhysicalSpoolDir(
	spoolDir string,
) (
	string,
	error,
) {
	resolved, err :=
		PhysicalSpoolPath(
			spoolDir,
		)
	if err != nil {
		return "", err
	}

	info, err :=
		os.Lstat(
			resolved,
		)
	if err != nil {
		return "", fmt.Errorf(
			"inspect physical FI spool directory: %w",
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() {
		return "", errors.New(
			"physical FI spool path must name a real directory",
		)
	}

	return resolved, nil
}

// CollectorWorkDir returns the physical same-volume working directory used for
// collector batches that are not yet ready for publication into the active
// spool. The returned directory is a sibling of the physical active spool so
// an active-spool rollover cannot move an in-progress collector batch.
func CollectorWorkDir(spoolDir string) (string, error) {
	resolved, err :=
		PhysicalSpoolDir(
			spoolDir,
		)
	if err != nil {
		return "", err
	}

	base :=
		filepath.Base(
			resolved,
		)

	if base == "." ||
		base == string(filepath.Separator) ||
		base == "" {
		return "", errors.New(
			"physical FI spool directory has invalid base name",
		)
	}

	workDir :=
		filepath.Join(
			filepath.Dir(
				resolved,
			),
			collectorWorkDirectoryPrefix+
				base+
				collectorWorkDirectorySuffix,
		)

	if filepath.Clean(workDir) ==
		filepath.Clean(resolved) {
		return "", errors.New(
			"FI collector work directory cannot equal active spool directory",
		)
	}

	return workDir, nil
}
