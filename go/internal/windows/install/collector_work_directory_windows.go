// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

const collectorWorkDirectoryACLLabel = "FI collector work directory"

func approval2OperationalDirectoryPaths(
	proposal ConfigState,
	handoff approval1PKIHandoff,
) ([]string, error) {
	workDir, err :=
		collectorWorkDirectoryPath(
			proposal.SpoolDir,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"derive FI collector work directory from approved spool path: %w",
			err,
		)
	}

	directories := []string{
		filepath.Dir(
			proposal.Path,
		),
		proposal.SpoolDir,
		workDir,
		proposal.StageDir,
		proposal.StateDir,
	}

	if handoff.complete() {
		directories = append(
			directories,
			filepath.Dir(
				handoff.CRLDestinationPath,
			),
		)
	}

	return directories, nil
}

func collectorWorkDirectoryPath(
	spoolDir string,
) (string, error) {
	spoolDir =
		strings.TrimSpace(
			spoolDir,
		)

	if spoolDir == "" {
		return "", errors.New(
			"FI spool directory is empty",
		)
	}

	spoolDir =
		filepath.Clean(
			spoolDir,
		)

	if !filepath.IsAbs(
		spoolDir,
	) {
		return "", fmt.Errorf(
			"FI spool directory is not absolute: %q",
			spoolDir,
		)
	}

	_, err :=
		os.Lstat(
			spoolDir,
		)

	switch {
	case err == nil:
		workDir, resolveErr :=
			spool.CollectorWorkDir(
				spoolDir,
			)
		if resolveErr != nil {
			return "", fmt.Errorf(
				"resolve physical FI collector work directory: %w",
				resolveErr,
			)
		}

		return filepath.Clean(
			workDir,
		), nil

	case errors.Is(
		err,
		os.ErrNotExist,
	):
		workDir, deriveErr :=
			spool.CollectorWorkPath(
				spoolDir,
			)
		if deriveErr != nil {
			return "", fmt.Errorf(
				"derive FI collector work directory: %w",
				deriveErr,
			)
		}

		return filepath.Clean(
			workDir,
		), nil

	default:
		return "", fmt.Errorf(
			"inspect configured FI spool directory %s: %w",
			spoolDir,
			err,
		)
	}
}

func collectorWorkDirectoryTarget(
	spoolDir string,
) string {
	path, err :=
		collectorWorkDirectoryPath(
			spoolDir,
		)
	if err != nil {
		return ""
	}

	return path
}
