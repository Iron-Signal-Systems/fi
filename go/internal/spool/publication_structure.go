// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidatePublishedSpoolStructureLocked verifies only the filesystem structure
// of the active published spool.
//
// The caller MUST already hold the FI publication boundary.
//
// This validation intentionally does not read manifests or batch data. Semantic
// verification belongs to the recorder. Rollover needs only to prove that the
// directory contains complete published batch pairs and nothing else before it
// freezes the directory for generation sealing.
func ValidatePublishedSpoolStructureLocked(
	spoolDir string,
) (
	pairs int,
	err error,
) {
	if spoolDir == "" ||
		!filepath.IsAbs(spoolDir) {
		return 0, errors.New(
			"FI published spool directory must be absolute",
		)
	}

	entries, err :=
		os.ReadDir(
			spoolDir,
		)
	if err != nil {
		return 0, fmt.Errorf(
			"read FI published spool directory: %w",
			err,
		)
	}

	data :=
		make(
			map[string]string,
		)

	manifests :=
		make(
			map[string]string,
		)

	for _, entry := range entries {

		name :=
			entry.Name()

		if entry.Type()&os.ModeSymlink != 0 {
			return 0, fmt.Errorf(
				"FI published spool artifact %q is a symbolic link",
				name,
			)
		}

		info, err :=
			entry.Info()
		if err != nil {
			return 0, fmt.Errorf(
				"inspect FI published spool artifact %q: %w",
				name,
				err,
			)
		}

		if !info.Mode().IsRegular() {
			return 0, fmt.Errorf(
				"FI published spool artifact %q is not a regular file",
				name,
			)
		}

		switch {
		case strings.HasPrefix(
			name,
			"batch-",
		) &&
			strings.HasSuffix(
				name,
				".manifest.json",
			):

			id :=
				strings.TrimSuffix(
					strings.TrimPrefix(
						name,
						"batch-",
					),
					".manifest.json",
				)

			if id == "" {
				return 0, fmt.Errorf(
					"FI published spool manifest %q has an empty batch ID",
					name,
				)
			}

			if _, exists :=
				manifests[id]; exists {
				return 0, fmt.Errorf(
					"FI published spool has duplicate manifest batch ID %q",
					id,
				)
			}

			manifests[id] =
				name

		case strings.HasPrefix(
			name,
			"batch-",
		) &&
			strings.HasSuffix(
				name,
				".jsonl",
			):

			id :=
				strings.TrimSuffix(
					strings.TrimPrefix(
						name,
						"batch-",
					),
					".jsonl",
				)

			if id == "" {
				return 0, fmt.Errorf(
					"FI published spool data file %q has an empty batch ID",
					name,
				)
			}

			if _, exists :=
				data[id]; exists {
				return 0, fmt.Errorf(
					"FI published spool has duplicate data batch ID %q",
					id,
				)
			}

			data[id] =
				name

		default:
			return 0, fmt.Errorf(
				"unexpected FI published spool artifact %q",
				name,
			)
		}
	}

	for id, dataName := range data {

		if _, exists :=
			manifests[id]; !exists {
			return 0, fmt.Errorf(
				"FI published spool data %q has no matching manifest",
				dataName,
			)
		}
	}

	for id, manifestName := range manifests {

		if _, exists :=
			data[id]; !exists {
			return 0, fmt.Errorf(
				"FI published spool manifest %q has no matching data file",
				manifestName,
			)
		}
	}

	return len(data), nil
}
