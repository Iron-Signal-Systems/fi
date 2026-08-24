// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/runtimeidentity"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

const spoolScopeID = "manual-test"

type spooledFileObservation struct {
	NTFS          ntfs.Observation               `json:"ntfs_observation"`
	ContentHashes records.ContentHashObservation `json:"content_hashes"`
}

type spooledCollectionError struct {
	PathDisplay          string `json:"path_display"`
	PathUTF16LEBase64URL string `json:"path_utf16le_base64url"`
	Error                string `json:"error"`
}

type spoolRunSummary struct {
	SpoolDir         string                 `json:"spool_dir"`
	TargetBatchSize  int                    `json:"target_batch_size"`
	FileObservations int                    `json:"file_observations"`
	CollectionErrors int                    `json:"collection_errors"`
	HashErrors       int                    `json:"hash_errors"`
	Batches          []spool.FinalizedBatch `json:"batches"`
	VerifiedBatches  int                    `json:"verified_batches"`
}

func runSpoolRoot(governedRoot string) {
	summary, err := writeSpoolRoot(context.Background(), governedRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
	writeIndentedJSON(summary)
}

func writeSpoolRoot(ctx context.Context, governedRoot string) (spoolRunSummary, error) {
	dir, err := spool.DefaultDir()
	if err != nil {
		return spoolRunSummary{}, err
	}
	executable, err := runtimeidentity.CurrentExecutable()
	if err != nil {
		return spoolRunSummary{}, err
	}
	writer, err := spool.NewWriter(dir, spool.DefaultBatchSize, spool.CollectorIdentity{
		ExecutablePath:   executable.Path,
		ExecutableSHA256: executable.SHA256,
	})
	if err != nil {
		return spoolRunSummary{}, err
	}

	summary := spoolRunSummary{SpoolDir: dir, TargetBatchSize: spool.DefaultBatchSize}
	walkErr := ntfs.WalkGovernedRoot(ctx, spoolScopeID, governedRoot, func(path string, observation ntfs.Observation, objectErr error) error {
		exactPath, err := pathUTF16LEBase64URL(path)
		if err != nil {
			return err
		}
		if objectErr != nil {
			summary.CollectionErrors++
			return writer.Append("NTFSCollectionError", spoolScopeID, spooledCollectionError{
				PathDisplay:          path,
				PathUTF16LEBase64URL: exactPath,
				Error:                objectErr.Error(),
			})
		}

		if observation.ContentHashes == nil {
			return errors.New("NTFS observation missing integrated content hashes")
		}
		hashes := *observation.ContentHashes
		if err := records.ValidateContentHashObservation(hashes); err != nil {
			return err
		}
		if hashes.State == records.ContentHashError {
			summary.HashErrors++
		}

		// Keep the established spool payload shape while ensuring collection is
		// already complete before batching. This copy only changes serialization;
		// it does not touch the source object again.
		spooledNTFS := observation
		spooledNTFS.ContentHashes = nil

		summary.FileObservations++
		return writer.Append("FileObservation", spoolScopeID, spooledFileObservation{
			NTFS:          spooledNTFS,
			ContentHashes: hashes,
		})
	})

	closeErr := writer.Close()
	summary.Batches = writer.FinalizedBatches()

	var verifyErr error
	for _, finalized := range summary.Batches {
		verification, err := spool.VerifyManifest(finalized.ManifestPath)
		if err != nil {
			verifyErr = errors.Join(verifyErr, err)
			continue
		}
		if !verification.Verified {
			verifyErr = errors.Join(verifyErr, errors.New("FI spool verification did not return verified=true"))
			continue
		}
		summary.VerifiedBatches++
	}

	if err := errors.Join(walkErr, closeErr, verifyErr); err != nil {
		return summary, err
	}
	return summary, nil
}

func runSpoolVerify(manifestPath string) {
	verification, err := spool.VerifyManifest(manifestPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
	writeIndentedJSON(verification)
}
