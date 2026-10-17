// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package generationrecorder

import (
	"fmt"
	"os"
	"path/filepath"
)

// recordedSourcePublicationDirectory requires pre-provisioned private
// directories. The recorder must not silently create its authoritative
// namespace or implicitly migrate legacy receipts.
func recordedSourcePublicationDirectory(
	recordedRoot string,
	sourceID string,
) (string, error) {
	sourceRoot, err := RecordedSourceDirectory(
		recordedRoot,
		sourceID,
	)
	if err != nil {
		return "", err
	}

	for _, directory := range []string{
		filepath.Join(recordedRoot, "sources"),
		sourceRoot,
	} {
		resolved, err := filepath.EvalSymlinks(directory)
		if err != nil {
			return "", fmt.Errorf(
				"resolve FI source receipt directory %q: %w",
				directory,
				err,
			)
		}

		if resolved != directory {
			return "", fmt.Errorf(
				"FI source receipt directory %q traverses a symlink",
				directory,
			)
		}

		info, err := os.Lstat(directory)
		if err != nil {
			return "", fmt.Errorf(
				"inspect FI source receipt directory %q: %w",
				directory,
				err,
			)
		}

		if !info.IsDir() ||
			info.Mode().Perm() != 0o700 {
			return "", fmt.Errorf(
				"FI source receipt directory %q must be a private 0700 directory",
				directory,
			)
		}
	}

	return sourceRoot, nil
}
