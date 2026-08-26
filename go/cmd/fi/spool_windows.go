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

type supportingSourceCollectionError struct {
	Source string `json:"source"`
	Error  string `json:"error"`
}

type spoolRunSummary struct {
	SpoolDir                  string                 `json:"spool_dir"`
	TargetBatchSize           int                    `json:"target_batch_size"`
	CollectorIdentityRecords  int                    `json:"collector_identity_records"`
	SMBShareSnapshotRecords   int                    `json:"smb_share_snapshot_records"`
	LocalPrincipalRecords     int                    `json:"local_principal_records"`
	DirectoryPrincipalRecords int                    `json:"directory_principal_records"`
	SupportingSourceErrors    int                    `json:"supporting_source_errors"`
	FileObservations          int                    `json:"file_observations"`
	CollectionErrors          int                    `json:"collection_errors"`
	HashErrors                int                    `json:"hash_errors"`
	Batches                   []spool.FinalizedBatch `json:"batches"`
	VerifiedBatches           int                    `json:"verified_batches"`
}

func runSpoolRoot(governedRoot string) {
	summary, err := writeSpoolRoot(context.Background(), spoolScopeID, governedRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
	writeIndentedJSON(summary)
}

func writeSpoolRoot(
	ctx context.Context,
	scopeID string,
	governedRoot string,
) (spoolRunSummary, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	// Gather the slower-changing supporting sources before opening the baseline
	// batch writer. Collector identity is required. SMB/local failures remain
	// explicit source errors and do not silently discard the NTFS baseline.
	supporting, err := collectSupportingSourceContext(ctx)
	if err != nil {
		return spoolRunSummary{}, err
	}

	dir, err := spool.DefaultDir()
	if err != nil {
		return spoolRunSummary{}, err
	}

	executable, err := runtimeidentity.CurrentExecutable()
	if err != nil {
		return spoolRunSummary{}, err
	}

	writer, err := spool.NewWriter(
		dir,
		spool.DefaultBatchSize,
		spool.CollectorIdentity{
			ExecutablePath:   executable.Path,
			ExecutableSHA256: executable.SHA256,
		},
	)
	if err != nil {
		return spoolRunSummary{}, err
	}

	summary := spoolRunSummary{
		SpoolDir:        dir,
		TargetBatchSize: spool.DefaultBatchSize,
	}

	if err := appendSupportingSourceStart(writer, scopeID, supporting, &summary); err != nil {
		closeErr := writer.Close()
		summary.Batches = writer.FinalizedBatches()
		return summary, errors.Join(err, closeErr)
	}

	walkErr := ntfs.WalkGovernedRoot(
		ctx,
		scopeID,
		governedRoot,
		func(path string, observation ntfs.Observation, objectErr error) error {
			exactPath, err := pathUTF16LEBase64URL(path)
			if err != nil {
				return err
			}

			if objectErr != nil {
				summary.CollectionErrors++
				return writer.Append(
					"NTFSCollectionError",
					scopeID,
					spooledCollectionError{
						PathDisplay:          path,
						PathUTF16LEBase64URL: exactPath,
						Error:                objectErr.Error(),
					},
				)
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

			// These SIDs are used only to select the relevant current-domain
			// principals for the final baseline directory snapshot.
			addNTFSObservationSIDs(supporting.ObservedSIDs, observation)

			// Keep the established FileObservation spool payload shape while
			// ensuring collection is already complete before batching. This
			// copy only changes serialization; it does not touch the source
			// object again.
			spooledNTFS := observation
			spooledNTFS.ContentHashes = nil

			summary.FileObservations++
			return writer.Append(
				"FileObservation",
				scopeID,
				spooledFileObservation{
					NTFS:          spooledNTFS,
					ContentHashes: hashes,
				},
			)
		},
	)

	var directoryErr error
	if walkErr == nil {
		directorySource := collectDirectorySource(
			ctx,
			supporting.CollectorIdentity,
			supporting.ObservedSIDs,
		)
		directoryErr = appendDirectorySource(
			writer,
			scopeID,
			directorySource,
			&summary,
		)
	}

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
			verifyErr = errors.Join(
				verifyErr,
				errors.New("FI spool verification did not return verified=true"),
			)
			continue
		}
		summary.VerifiedBatches++
	}

	if err := errors.Join(walkErr, directoryErr, closeErr, verifyErr); err != nil {
		return summary, err
	}

	return summary, nil
}

func appendSupportingSourceStart(
	writer *spool.Writer,
	scopeID string,
	supporting supportingSourceContext,
	summary *spoolRunSummary,
) error {
	if writer == nil {
		return errors.New("spool writer is required")
	}
	if summary == nil {
		return errors.New("spool summary is required")
	}

	if err := writer.Append(
		"CollectorIdentity",
		scopeID,
		supporting.CollectorIdentity,
	); err != nil {
		return err
	}
	summary.CollectorIdentityRecords++

	if supporting.SMBShareError != "" {
		if err := appendSupportingSourceError(
			writer,
			scopeID,
			"SMBShareSnapshot",
			supporting.SMBShareError,
		); err != nil {
			return err
		}
		summary.SupportingSourceErrors++
	} else {
		if supporting.SMBShareSnapshot == nil {
			return errors.New("SMB supporting source contains neither snapshot nor explicit error")
		}
		if err := writer.Append(
			"SMBShareSnapshot",
			scopeID,
			*supporting.SMBShareSnapshot,
		); err != nil {
			return err
		}
		summary.SMBShareSnapshotRecords++
	}

	if supporting.LocalPrincipalError != "" {
		if err := appendSupportingSourceError(
			writer,
			scopeID,
			"LocalPrincipalSnapshot",
			supporting.LocalPrincipalError,
		); err != nil {
			return err
		}
		summary.SupportingSourceErrors++
	} else {
		if supporting.LocalPrincipals == nil {
			return errors.New("local identity source contains neither snapshot nor explicit error")
		}
		if err := writer.Append(
			"LocalPrincipalSnapshot",
			scopeID,
			*supporting.LocalPrincipals,
		); err != nil {
			return err
		}
		summary.LocalPrincipalRecords++
	}

	return nil
}

func appendDirectorySource(
	writer *spool.Writer,
	scopeID string,
	source directorySourceResult,
	summary *spoolRunSummary,
) error {
	if writer == nil {
		return errors.New("spool writer is required")
	}
	if summary == nil {
		return errors.New("spool summary is required")
	}

	if source.Error != "" {
		if err := appendSupportingSourceError(
			writer,
			scopeID,
			"DirectoryPrincipalSnapshot",
			source.Error,
		); err != nil {
			return err
		}
		summary.SupportingSourceErrors++
		return nil
	}

	if source.Snapshot == nil {
		return errors.New("directory source contains neither snapshot nor explicit error")
	}

	if err := writer.Append(
		"DirectoryPrincipalSnapshot",
		scopeID,
		*source.Snapshot,
	); err != nil {
		return err
	}
	summary.DirectoryPrincipalRecords++
	return nil
}

func appendSupportingSourceError(
	writer *spool.Writer,
	scopeID string,
	source string,
	sourceErr string,
) error {
	if source == "" || sourceErr == "" {
		return errors.New("supporting source error requires source and error")
	}

	return writer.Append(
		"SupportingSourceCollectionError",
		scopeID,
		supportingSourceCollectionError{
			Source: source,
			Error:  sourceErr,
		},
	)
}

func runSpoolVerify(manifestPath string) {
	verification, err := spool.VerifyManifest(manifestPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
	writeIndentedJSON(verification)
}
