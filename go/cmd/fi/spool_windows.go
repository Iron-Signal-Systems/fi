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
	Batches          []spool.FinalizedBatch `json:"batches"`
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

		hashes, hashErr := ntfs.CollectContentHashes(ctx, spoolScopeID, governedRoot, observation.ObjectIdentity, observation.SubjectKind)
		if hashErr != nil {
			hashes = records.ContentHashObservation{
				State:      records.ContentHashError,
				ReasonCode: "HashCollectionFailed",
				Detail:     hashErr.Error(),
			}
		}
		if err := records.ValidateContentHashObservation(hashes); err != nil {
			return err
		}

		summary.FileObservations++
		return writer.Append("FileObservation", spoolScopeID, spooledFileObservation{
			NTFS:          observation,
			ContentHashes: hashes,
		})
	})

	closeErr := writer.Close()
	summary.Batches = writer.FinalizedBatches()
	if walkErr != nil || closeErr != nil {
		return summary, errors.Join(walkErr, closeErr)
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
