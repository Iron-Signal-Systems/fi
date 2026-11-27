// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"errors"
	"fmt"
	"reflect"
)

// ErrWriterPendingFinalization means a previously accepted batch has not yet
// completed publication. Additional records must not be accepted until Close
// successfully resolves that batch.
var ErrWriterPendingFinalization = errors.New(
	"FI spool writer has a batch pending finalization",
)

type preparedBatch struct {
	openPath         string
	workDataPath     string
	workManifestPath string
	dataName         string
	manifestName     string
	manifest         Manifest
	dataPrepared     bool
	manifestPrepared bool
}

// finishPendingBatch completes a finalized in-memory batch without accepting
// any additional records.
//
// The normal path does not add another semantic data-file read. If a retry
// discovers that a previous filesystem operation may already have completed,
// the existing batch is independently verified before the state is accepted.
func (w *Writer) finishPendingBatch() error {
	if w == nil ||
		w.pending == nil {
		return nil
	}

	if w.file != nil {
		return errors.New(
			"FI spool writer has pending finalization while data file remains open",
		)
	}

	pending :=
		w.pending

	if !pending.dataPrepared {
		openExists, err :=
			recoveryRegularFileExists(
				pending.openPath,
			)
		if err != nil {
			return err
		}

		workDataExists, err :=
			recoveryRegularFileExists(
				pending.workDataPath,
			)
		if err != nil {
			return err
		}

		switch {
		case openExists &&
			workDataExists:
			return errors.New(
				"FI pending batch has both open and completed work data",
			)

		case openExists:
			if err :=
				durableRename(
					pending.openPath,
					pending.workDataPath,
				); err != nil {
				return fmt.Errorf(
					"promote completed FI collector work data: %w",
					err,
				)
			}

			pending.dataPrepared =
				true

		case workDataExists:
			// This state is reached only when a prior rename may have
			// completed even though the caller did not observe success.
			// Re-establish the expected bytes/hash/count before trusting it.
			if err :=
				verifyPreparedManifestAgainstData(
					pending.manifest,
					pending.workDataPath,
				); err != nil {
				return fmt.Errorf(
					"verify retried FI collector work data: %w",
					err,
				)
			}

			pending.dataPrepared =
				true

		default:
			return errors.New(
				"FI pending batch data is missing from collector work state",
			)
		}
	}

	if !pending.manifestPrepared {
		workManifestExists, err :=
			recoveryRegularFileExists(
				pending.workManifestPath,
			)
		if err != nil {
			return err
		}

		if workManifestExists {
			// A prior manifest operation may have completed before its
			// caller observed an error. Verify both identity and pair.
			if err :=
				verifyExpectedManifestFile(
					pending.workManifestPath,
					pending.manifest,
				); err != nil {
				return err
			}

			verification, err :=
				VerifyManifest(
					pending.workManifestPath,
				)
			if err != nil {
				return fmt.Errorf(
					"verify retried FI collector work manifest: %w",
					err,
				)
			}

			if !verification.Verified {
				return errors.New(
					"retried FI collector work manifest did not verify",
				)
			}

			pending.manifestPrepared =
				true
		} else {
			if err :=
				writeManifest(
					pending.workManifestPath,
					pending.manifest,
				); err != nil {
				return err
			}

			pending.manifestPrepared =
				true
		}
	}

	dataPath, manifestPath, err :=
		w.publishPreparedBatch(
			pending.workDataPath,
			pending.workManifestPath,
			pending.dataName,
			pending.manifestName,
			pending.manifest,
		)
	if err != nil {
		return err
	}

	w.finalized =
		append(
			w.finalized,
			FinalizedBatch{
				DataPath:     dataPath,
				ManifestPath: manifestPath,
				Manifest:     pending.manifest,
			},
		)

	w.pending =
		nil

	w.resetCurrent()

	return nil
}

func verifyExpectedManifestFile(
	path string,
	expected Manifest,
) error {
	actual, err :=
		readPreparedPublicationManifest(
			path,
		)
	if err != nil {
		return fmt.Errorf(
			"read FI prepared manifest for retry: %w",
			err,
		)
	}

	if !reflect.DeepEqual(
		actual,
		expected,
	) {
		return errors.New(
			"FI prepared manifest does not match writer pending state",
		)
	}

	return nil
}
