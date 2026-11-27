// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// RecoverAbandonedPublications is intended for collector startup before new
// writers begin producing batches.
//
// A complete prepared pair left in the collector work directory is treated as
// abandoned work from a prior collector process. The pair is independently
// verified and published while holding the normal publication boundary.
//
// An interrupted publication in which the data file already reached the active
// spool but the manifest remains in the work directory is also completed.
//
// Incomplete .open artifacts are deliberately ignored here. They are not
// completed batches and require a separate abandoned-work cleanup policy.
func RecoverAbandonedPublications(
	spoolDir string,
) (
	recovered int,
	returnErr error,
) {
	guard, err :=
		AcquirePublishBoundary()
	if err != nil {
		return 0, fmt.Errorf(
			"acquire FI spool publication boundary for startup recovery: %w",
			err,
		)
	}

	defer func() {
		returnErr =
			errors.Join(
				returnErr,
				guard.Close(),
			)
	}()

	recovered, err =
		recoverPreparedPublicationsLocked(
			spoolDir,
			true,
		)
	if err != nil {
		return recovered, err
	}

	if err :=
		salvageStartupManifestOpensLocked(
			spoolDir,
		); err != nil {
		return recovered, err
	}

	additional, err :=
		recoverPreparedPublicationsLocked(
			spoolDir,
			true,
		)
	if err != nil {
		return recovered, err
	}

	recovered +=
		additional

	if err :=
		quarantineStartupIncompleteArtifactsLocked(
			spoolDir,
		); err != nil {
		return recovered, err
	}

	return recovered, nil
}

// RecoverInterruptedPublicationsLocked repairs only a publication that had
// already begun.
//
// The caller MUST already hold the FI publication boundary.
//
// A work-directory pair that has not begun publication is ignored because it
// may belong to a live collector writer waiting for the same boundary. This
// makes the function safe for generation rollover to call after acquiring the
// publication boundary.
func RecoverInterruptedPublicationsLocked(
	spoolDir string,
) (
	int,
	error,
) {
	return recoverPreparedPublicationsLocked(
		spoolDir,
		false,
	)
}

func recoverPreparedPublicationsLocked(
	spoolDir string,
	includeUnstartedPrepared bool,
) (
	int,
	error,
) {
	if spoolDir == "" ||
		!filepath.IsAbs(spoolDir) {
		return 0, errors.New(
			"FI spool directory must be absolute",
		)
	}

	publicationDir, err :=
		resolveDirectoryPath(
			filepath.Clean(spoolDir),
		)
	if err != nil {
		return 0, fmt.Errorf(
			"resolve FI publication directory for recovery: %w",
			err,
		)
	}

	publicationInfo, err :=
		os.Lstat(
			publicationDir,
		)
	if err != nil {
		return 0, fmt.Errorf(
			"inspect FI publication directory for recovery: %w",
			err,
		)
	}

	if publicationInfo.Mode()&os.ModeSymlink != 0 ||
		!publicationInfo.IsDir() {
		return 0, errors.New(
			"FI publication recovery path must name a real directory",
		)
	}

	workDir, err :=
		CollectorWorkDir(
			spoolDir,
		)
	if err != nil {
		return 0, err
	}

	workInfo, err :=
		os.Lstat(
			workDir,
		)

	if errors.Is(
		err,
		os.ErrNotExist,
	) {
		return 0, nil
	}

	if err != nil {
		return 0, fmt.Errorf(
			"inspect FI collector work directory for recovery: %w",
			err,
		)
	}

	if workInfo.Mode()&os.ModeSymlink != 0 ||
		!workInfo.IsDir() {
		return 0, errors.New(
			"FI collector recovery work path must name a real directory",
		)
	}

	entries, err :=
		os.ReadDir(
			workDir,
		)
	if err != nil {
		return 0, fmt.Errorf(
			"scan FI collector work directory for recovery: %w",
			err,
		)
	}

	recovered :=
		0

	for _, entry := range entries {

		name :=
			entry.Name()

		if !strings.HasPrefix(
			name,
			"batch-",
		) ||
			!strings.HasSuffix(
				name,
				".manifest.json",
			) {
			continue
		}

		if entry.Type()&os.ModeSymlink != 0 ||
			!entry.Type().IsRegular() {
			return recovered, fmt.Errorf(
				"FI prepared publication manifest %q is not a regular file",
				name,
			)
		}

		workManifestPath :=
			filepath.Join(
				workDir,
				name,
			)

		manifest, err :=
			readPreparedPublicationManifest(
				workManifestPath,
			)
		if err != nil {
			return recovered, fmt.Errorf(
				"read prepared FI publication manifest %q: %w",
				name,
				err,
			)
		}

		expectedManifestName :=
			"batch-" +
				manifest.BatchID +
				".manifest.json"

		if name !=
			expectedManifestName {
			return recovered, fmt.Errorf(
				"prepared FI publication manifest name %q does not match batch ID %q",
				name,
				manifest.BatchID,
			)
		}

		workDataPath :=
			filepath.Join(
				workDir,
				manifest.DataFile,
			)

		publicationDataPath :=
			filepath.Join(
				publicationDir,
				manifest.DataFile,
			)

		publicationManifestPath :=
			filepath.Join(
				publicationDir,
				expectedManifestName,
			)

		workDataExists, err :=
			recoveryRegularFileExists(
				workDataPath,
			)
		if err != nil {
			return recovered, err
		}

		publicationDataExists, err :=
			recoveryRegularFileExists(
				publicationDataPath,
			)
		if err != nil {
			return recovered, err
		}

		publicationManifestExists, err :=
			recoveryRegularFileExists(
				publicationManifestPath,
			)
		if err != nil {
			return recovered, err
		}

		if publicationManifestExists {
			return recovered, fmt.Errorf(
				"prepared FI publication %q conflicts with an already-published manifest",
				manifest.BatchID,
			)
		}

		switch {

		case workDataExists &&
			publicationDataExists:

			return recovered, fmt.Errorf(
				"prepared FI publication %q has duplicate work and published data files",
				manifest.BatchID,
			)

		case publicationDataExists:

			if err :=
				verifyPreparedManifestAgainstData(
					manifest,
					publicationDataPath,
				); err != nil {
				return recovered, fmt.Errorf(
					"verify interrupted FI publication %q: %w",
					manifest.BatchID,
					err,
				)
			}

			if err :=
				durableRename(
					workManifestPath,
					publicationManifestPath,
				); err != nil {
				return recovered, fmt.Errorf(
					"complete interrupted FI publication %q: %w",
					manifest.BatchID,
					err,
				)
			}

			recovered++

		case workDataExists:

			if !includeUnstartedPrepared {
				continue
			}

			verification, err :=
				VerifyManifest(
					workManifestPath,
				)
			if err != nil {
				return recovered, fmt.Errorf(
					"verify abandoned prepared FI publication %q: %w",
					manifest.BatchID,
					err,
				)
			}

			if !verification.Verified {
				return recovered, fmt.Errorf(
					"abandoned prepared FI publication %q did not verify",
					manifest.BatchID,
				)
			}

			if err :=
				requirePublicationPathAbsent(
					publicationDataPath,
				); err != nil {
				return recovered, err
			}

			if err :=
				requirePublicationPathAbsent(
					publicationManifestPath,
				); err != nil {
				return recovered, err
			}

			if err :=
				durableRename(
					workDataPath,
					publicationDataPath,
				); err != nil {
				return recovered, fmt.Errorf(
					"publish abandoned FI batch data %q: %w",
					manifest.BatchID,
					err,
				)
			}

			if err :=
				durableRename(
					workManifestPath,
					publicationManifestPath,
				); err != nil {

				rollbackErr :=
					durableRename(
						publicationDataPath,
						workDataPath,
					)

				if rollbackErr != nil {
					return recovered, errors.Join(
						fmt.Errorf(
							"publish abandoned FI batch manifest %q: %w",
							manifest.BatchID,
							err,
						),
						fmt.Errorf(
							"rollback abandoned FI batch data %q: %w",
							manifest.BatchID,
							rollbackErr,
						),
					)
				}

				return recovered, fmt.Errorf(
					"publish abandoned FI batch manifest %q: %w",
					manifest.BatchID,
					err,
				)
			}

			recovered++

		default:

			return recovered, fmt.Errorf(
				"prepared FI publication %q has a manifest but no matching data file",
				manifest.BatchID,
			)
		}
	}

	return recovered, nil
}

func readPreparedPublicationManifest(
	path string,
) (
	Manifest,
	error,
) {
	file, err :=
		os.Open(
			path,
		)
	if err != nil {
		return Manifest{}, err
	}

	decoder :=
		json.NewDecoder(
			file,
		)

	decoder.DisallowUnknownFields()

	var manifest Manifest

	if err :=
		decoder.Decode(
			&manifest,
		); err != nil {
		_ = file.Close()
		return Manifest{}, err
	}

	var extra any

	if err :=
		decoder.Decode(
			&extra,
		); err != io.EOF {
		_ = file.Close()

		return Manifest{}, errors.New(
			"manifest contains trailing data",
		)
	}

	if err :=
		file.Close(); err != nil {
		return Manifest{}, err
	}

	if err :=
		validateManifest(
			manifest,
		); err != nil {
		return Manifest{}, err
	}

	return manifest, nil
}

func verifyPreparedManifestAgainstData(
	manifest Manifest,
	dataPath string,
) error {
	digest, dataBytes, records, err :=
		inspectDataFile(
			dataPath,
		)
	if err != nil {
		return err
	}

	if digest !=
		manifest.DataSHA256 {
		return ErrBatchHashMismatch
	}

	if dataBytes !=
		manifest.DataBytes {
		return ErrBatchSizeMismatch
	}

	if records !=
		manifest.RecordCount {
		return ErrBatchCountMismatch
	}

	return nil
}

func recoveryRegularFileExists(
	path string,
) (
	bool,
	error,
) {
	info, err :=
		os.Lstat(
			path,
		)

	if errors.Is(
		err,
		os.ErrNotExist,
	) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf(
			"inspect FI publication recovery path %q: %w",
			path,
			err,
		)
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() {
		return false, fmt.Errorf(
			"FI publication recovery path %q is not a regular file",
			path,
		)
	}

	return true, nil
}
