// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package releaselab

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func BuildSignedInstaller(
	keysDirectory string,
	installerPath string,
	outputPath string,
) (string, error) {
	if strings.TrimSpace(
		keysDirectory,
	) == "" ||
		strings.TrimSpace(
			installerPath,
		) == "" ||
		strings.TrimSpace(
			outputPath,
		) == "" {
		return "", fmt.Errorf(
			"keys, installer input, and output path are required",
		)
	}

	output, err := filepath.Abs(
		outputPath,
	)
	if err != nil {
		return "", fmt.Errorf(
			"resolve signed installer output path: %w",
			err,
		)
	}
	if _, err := os.Stat(
		output,
	); err == nil {
		return "", fmt.Errorf(
			"refusing to overwrite existing signed installer %s",
			output,
		)
	} else if !os.IsNotExist(
		err,
	) {
		return "", fmt.Errorf(
			"stat signed installer output %s: %w",
			output,
			err,
		)
	}

	if err := os.MkdirAll(
		filepath.Dir(
			output,
		),
		0o755,
	); err != nil {
		return "", fmt.Errorf(
			"create signed installer output directory: %w",
			err,
		)
	}

	if err := copyRegularFile(
		installerPath,
		output,
	); err != nil {
		return "", err
	}

	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(
				output,
			)
		}
	}()

	if err := SignAuthenticodeFile(
		keysDirectory,
		output,
	); err != nil {
		return "", fmt.Errorf(
			"Authenticode-sign fi-install.exe: %w",
			err,
		)
	}

	hash, err := fileSHA256(
		output,
	)
	if err != nil {
		return "", err
	}

	cleanup = false
	return hash, nil
}
