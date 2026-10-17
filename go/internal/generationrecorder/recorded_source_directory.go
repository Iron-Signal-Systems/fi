// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package generationrecorder

import (
	"errors"
	"path/filepath"
	"strings"
)

// RecordedSourceDirectory returns the authoritative source-specific
// receipt directory. This function does not create directories.
func RecordedSourceDirectory(
	recordedRoot string,
	sourceID string,
) (string, error) {
	if recordedRoot == "" ||
		!filepath.IsAbs(recordedRoot) ||
		filepath.Clean(recordedRoot) != recordedRoot {
		return "", errors.New(
			"FI recorded receipt root must be a clean absolute path",
		)
	}

	if sourceID == "" ||
		sourceID == "." ||
		sourceID == ".." ||
		strings.ContainsAny(sourceID, "/\\\x00") {
		return "", errors.New(
			"FI recorded receipt source identity is invalid",
		)
	}

	return filepath.Join(
		recordedRoot,
		"sources",
		sourceID,
	), nil
}
