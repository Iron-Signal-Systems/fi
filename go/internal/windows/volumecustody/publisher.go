// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package volumecustody

import (
	"context"
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumeepoch"
)

// ErrWindowSplit means the FI spool writer finalized a batch before a complete
// terminal-boundary record had been published, or emitted more than one batch.
// Any already-published file is IN DOUBT, and is not removed automatically.
var ErrWindowSplit = errors.New("FI volume-first source window cannot be published as one complete batch")

// OneBatchSpoolPublisher is a concrete implementation of WindowPublisher.
// It uses the existing FI spool writer, its hash/manifest publication protocol
// and a SECOND post-publication verification pass. This publisher does not
// select any native volume, verify an installed grant, or advance a checkpoint.
//
// The caller must provide a trusted, ACL-protected FI spool directory and a
// previously authenticated collector executable identity. A single batch
// cannot represent an unbounded source window or a multi-batch transaction.
type OneBatchSpoolPublisher struct {
	Directory string
	Collector spool.CollectorIdentity
}

// PublishWindow makes a single, complete window visible as FI spool custody.
// It returns a manifest only if the entire terminal-boundary batch is visible
// and verified. When a publication failure occurs after data was written,
// unfinished work is closed WITHOUT finalization or deletion; already
// published artifacts are retained for operator-visible recovery.
func (publisher OneBatchSpoolPublisher) PublishWindow(
	ctx context.Context,
	window Window,
) (manifestPath string, returnErr error) {
	if ctx == nil {
		return "", fmt.Errorf("%w: publication context required", ErrUnsafeWindow)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	// Shape-check source records WITHOUT claiming this synthesized journal is
	// a native source attestation. ProcessOneWindow separately obtains the
	// actual, independently authenticated journal before calling Publisher.
	boundary := window.Boundary
	shapeCheckpoint := volumeepoch.Checkpoint{
		Version: volumeepoch.CheckpointVersion,
		EnrollmentID: boundary.EnrollmentID,
		Epoch: boundary.Epoch,
		Identity: boundary.Identity,
		NextUSN: boundary.StartUSN,
	}
	shapeJournal := volumeepoch.Journal{
		Identity: boundary.Identity,
		FirstUSN: boundary.StartUSN,
		LowestValidUSN: "0",
		NextUSN: boundary.NextUSN,
	}
	if err := validateWindow(shapeCheckpoint, shapeJournal, window); err != nil {
		return "", err
	}

	// Leave room for the mandatory boundary: a count-based automatic
	// rollover must never publish a partial window. Byte-sized rollovers or
	// a stricter configured policy still require explicit detection below.
	writer, err := spool.NewWriter(
		publisher.Directory, len(window.Changes)+2, publisher.Collector,
	)
	if err != nil {
		return "", fmt.Errorf("create FI single-window spool writer: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			returnErr = errors.Join(returnErr, writer.AbandonUnpublished())
		}
	}()
	scopeID := "volume:" + boundary.EnrollmentID
	for index, change := range window.Changes {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := writer.Append(MinimalFactRecordKind, scopeID, change); err != nil {
			return "", fmt.Errorf("write FI volume source fact %d: %w", index, err)
		}
		if len(writer.FinalizedBatches()) != 0 {
			return "", fmt.Errorf("%w: FI spool rollover before terminal source boundary", ErrWindowSplit)
		}
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := writer.Append(BoundaryRecordKind, scopeID, boundary); err != nil {
		return "", fmt.Errorf("write terminal FI volume source boundary: %w", err)
	}
	if len(writer.FinalizedBatches()) > 1 {
		return "", fmt.Errorf("%w: terminal append produced multiple batches", ErrWindowSplit)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", fmt.Errorf("finalize complete FI source window: %w", err)
	}
	closed = true
	batches := writer.FinalizedBatches()
	if len(batches) != 1 || batches[0].Manifest.RecordCount != len(window.Changes)+1 {
		return "", fmt.Errorf("%w: expected exactly one complete published manifest/data pair", ErrWindowSplit)
	}
	manifestPath = batches[0].ManifestPath
	if err := ctx.Err(); err != nil {
		return manifestPath, err // publication succeeded, acknowledgement uncertain
	}
	verification, err := spool.VerifyManifest(manifestPath)
	if err != nil || !verification.Verified ||
		verification.Manifest.BatchID != batches[0].Manifest.BatchID ||
		verification.Manifest.RecordCount != len(window.Changes)+1 ||
		verification.DataPath != batches[0].DataPath {
		return manifestPath, fmt.Errorf("%w: post-publication spool pair failed independent verification: %v",
			ErrUnverifiedCustody, err)
	}
	return manifestPath, nil
}
