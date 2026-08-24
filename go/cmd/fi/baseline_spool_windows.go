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
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/checkpoint"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usn"
)

var (
	ErrBaselineCollectionIncomplete = errors.New("baseline collection incomplete")
	ErrBaselineAnchorGap            = errors.New("pre-baseline USN anchor is no longer continuous")
)

// baselineAnchor is captured before the recursive baseline starts. Its NextUSN
// becomes the initial checkpoint only after the baseline batches have been
// finalized and verified. This makes changes that occur during the baseline
// eligible for the first USN catch-up pass.
type baselineAnchor struct {
	GovernedRoot records.GovernedRootIdentity `json:"governed_root"`
	JournalState records.USNJournalState      `json:"journal_state"`
}

type baselineSpoolSummary struct {
	StatePath              string                           `json:"state_path"`
	Anchor                 baselineAnchor                   `json:"anchor"`
	Baseline               spoolRunSummary                  `json:"baseline"`
	PostBaselineAssessment *checkpoint.ContinuityAssessment `json:"post_baseline_assessment,omitempty"`
	CheckpointInitialized  bool                             `json:"checkpoint_initialized"`
	Checkpoint             *checkpoint.USNCheckpoint        `json:"checkpoint,omitempty"`
	Semantics              string                           `json:"semantics"`
}

func runBaselineSpoolRoot(governedRoot string) {
	summary, err := writeBaselineSpoolRoot(context.Background(), spoolScopeID, governedRoot)
	if err != nil {
		if summary.StatePath != "" {
			writeIndentedJSON(summary)
		}
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
	writeIndentedJSON(summary)
}

func writeBaselineSpoolRoot(ctx context.Context, scopeID string, governedRoot string) (baselineSpoolSummary, error) {
	statePath, err := checkpoint.DefaultPath(scopeID)
	if err != nil {
		return baselineSpoolSummary{}, err
	}

	summary := baselineSpoolSummary{
		StatePath: statePath,
		Semantics: "FI captures the USN position before baseline collection, writes and verifies the baseline batches, then initializes the checkpoint to that original pre-baseline USN. The first USN catch-up therefore includes changes that occurred while the baseline was running.",
	}

	anchor, err := captureBaselineAnchor(ctx, scopeID, governedRoot)
	if err != nil {
		return summary, err
	}
	summary.Anchor = anchor

	baseline, err := writeSpoolRoot(ctx, governedRoot)
	summary.Baseline = baseline
	if err != nil {
		return summary, err
	}
	if err := validateBaselineSpoolForCheckpoint(baseline); err != nil {
		return summary, err
	}

	assessment, candidate, err := prepareCheckpointFromBaselineAnchor(ctx, scopeID, governedRoot, anchor)
	summary.PostBaselineAssessment = &assessment
	if err != nil {
		return summary, err
	}

	if err := checkpoint.Save(statePath, candidate); err != nil {
		return summary, err
	}

	persisted, err := checkpoint.Load(statePath)
	if err != nil {
		return summary, err
	}
	if persisted.ScopeID != candidate.ScopeID || persisted.JournalID != candidate.JournalID || persisted.NextUSN != candidate.NextUSN {
		return summary, errors.New("persisted baseline checkpoint does not match prepared checkpoint")
	}

	summary.CheckpointInitialized = true
	summary.Checkpoint = &persisted
	return summary, nil
}

func captureBaselineAnchor(ctx context.Context, scopeID string, governedRoot string) (baselineAnchor, error) {
	rootObservation, err := ntfs.CollectPath(ctx, scopeID, governedRoot, governedRoot)
	if err != nil {
		return baselineAnchor{}, err
	}
	journal, err := usn.QueryJournal(ctx, scopeID, governedRoot)
	if err != nil {
		return baselineAnchor{}, err
	}
	if !sameVolumeIdentity(rootObservation.GovernedRoot.VolumeIdentity, journal.VolumeIdentity) {
		return baselineAnchor{}, errors.New("pre-baseline governed root and USN journal volume identities do not match")
	}
	return baselineAnchor{
		GovernedRoot: rootObservation.GovernedRoot,
		JournalState: journal,
	}, nil
}

func prepareCheckpointFromBaselineAnchor(
	ctx context.Context,
	scopeID string,
	governedRoot string,
	anchor baselineAnchor,
) (checkpoint.ContinuityAssessment, checkpoint.USNCheckpoint, error) {
	rootObservation, err := ntfs.CollectPath(ctx, scopeID, governedRoot, governedRoot)
	if err != nil {
		return checkpoint.ContinuityAssessment{}, checkpoint.USNCheckpoint{}, err
	}
	journal, err := usn.QueryJournal(ctx, scopeID, governedRoot)
	if err != nil {
		return checkpoint.ContinuityAssessment{}, checkpoint.USNCheckpoint{}, err
	}

	candidate := checkpoint.USNCheckpoint{
		Version:      checkpoint.SchemaVersion,
		ScopeID:      scopeID,
		GovernedRoot: anchor.GovernedRoot,
		JournalID:    anchor.JournalState.JournalID,
		NextUSN:      anchor.JournalState.NextUSN,
		UpdatedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	assessment, err := checkpoint.Assess(candidate, rootObservation.GovernedRoot, journal)
	if err != nil {
		return checkpoint.ContinuityAssessment{}, checkpoint.USNCheckpoint{}, err
	}
	if assessment.Status != checkpoint.ContinuityContinuous {
		return assessment, checkpoint.USNCheckpoint{}, fmt.Errorf("%w: %s", ErrBaselineAnchorGap, assessment.ReasonCode)
	}
	return assessment, candidate, nil
}

func validateBaselineSpoolForCheckpoint(summary spoolRunSummary) error {
	switch {
	case summary.CollectionErrors != 0:
		return fmt.Errorf("%w: %d NTFS collection errors", ErrBaselineCollectionIncomplete, summary.CollectionErrors)
	case summary.HashErrors != 0:
		return fmt.Errorf("%w: %d content hash errors", ErrBaselineCollectionIncomplete, summary.HashErrors)
	case summary.FileObservations == 0:
		return fmt.Errorf("%w: no NTFS observations were collected", ErrBaselineCollectionIncomplete)
	case len(summary.Batches) == 0:
		return fmt.Errorf("%w: no finalized baseline batches", ErrBaselineCollectionIncomplete)
	case summary.VerifiedBatches != len(summary.Batches):
		return fmt.Errorf("%w: verified %d of %d baseline batches", ErrBaselineCollectionIncomplete, summary.VerifiedBatches, len(summary.Batches))
	default:
		return nil
	}
}

func sameVolumeIdentity(left records.VolumeIdentity, right records.VolumeIdentity) bool {
	return left.VolumeGUID == right.VolumeGUID && left.VolumeSerial == right.VolumeSerial
}
