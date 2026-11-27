// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build !windows

package transportgeneration

import (
	"fmt"
	"os"
	"path/filepath"
)

func publishGenerationPayload(
	provisionalPath string,
	finalPath string,
) error {
	return os.Rename(
		provisionalPath,
		finalPath,
	)
}

func publishGenerationDirectory(
	provisionalPath string,
	finalPath string,
) error {
	// Both durable files already have their contents fsynced. Syncing the
	// provisional directory makes the payload rename and metadata directory
	// entry durable before the directory itself becomes visible as final.
	if err :=
		syncGenerationDirectory(
			provisionalPath,
		); err != nil {
		return fmt.Errorf(
			"sync provisional FI sealed-generation directory: %w",
			err,
		)
	}

	if err :=
		os.Rename(
			provisionalPath,
			finalPath,
		); err != nil {
		return err
	}

	// Persist the namespace transition from provisional name to final name.
	if err :=
		syncGenerationDirectory(
			filepath.Dir(
				finalPath,
			),
		); err != nil {
		return fmt.Errorf(
			"sync FI sealed-generation parent directory: %w",
			err,
		)
	}

	return nil
}

func syncGenerationDirectory(
	path string,
) error {
	directory, err :=
		os.Open(
			path,
		)
	if err != nil {
		return err
	}

	if err :=
		directory.Sync(); err != nil {
		_ =
			directory.Close()

		return err
	}

	return directory.Close()
}
