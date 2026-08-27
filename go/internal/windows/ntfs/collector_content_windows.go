// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"sort"
	"syscall"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

// collectOpenedTargetWithContentHashes completes one FI object observation
// before the public collection call returns. The original target handle remains
// open while FI reopens the exact same NTFS object identity with GENERIC_READ
// for the one-pass content hash. The spool layer therefore never needs to go
// back to the source object to add hashes.
func collectOpenedTargetWithContentHashes(
	ctx context.Context,
	root governedRootContext,
	entryMethod CollectionEntryMethod,
	targetPath []uint16,
	targetHandle syscall.Handle,
	expectedIdentity *records.NTFSObjectIdentity,
) (Observation, error) {
	observation, err := collectOpenedTarget(
		ctx,
		root,
		entryMethod,
		targetPath,
		targetHandle,
		expectedIdentity,
	)
	if err != nil {
		return Observation{}, err
	}

	var hashes records.ContentHashObservation
	if observation.Reparse.State == records.ReparseStatePresent {
		hashes = records.ContentHashObservation{State: records.ContentHashNotApplicable}
	} else {
		hashes, err = collectContentHashesOpened(
			ctx,
			root,
			targetHandle,
			observation.ObjectIdentity,
			observation.SubjectKind,
		)
		if err != nil {
			return Observation{}, err
		}
	}
	if err := records.ValidateContentHashObservation(hashes); err != nil {
		return Observation{}, err
	}

	observation.ContentHashes = &hashes
	applyContentHashOutcome(&observation, hashes)
	observation.ObservedAt = time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
	if err := ValidateObservation(observation); err != nil {
		return Observation{}, &Error{Stage: StageMetadata, Op: "ValidateObservationWithContentHashes", Err: err}
	}
	return observation, nil
}

// applyContentHashOutcome keeps content-hash failure visible at the whole-object
// observation boundary. The detailed hash record still carries the exact
// reason, while ContentHashFailed prevents a failed file-content read from being
// represented as a fully Complete observation.
func applyContentHashOutcome(
	observation *Observation,
	hashes records.ContentHashObservation,
) {
	if observation == nil || hashes.State != records.ContentHashError {
		return
	}

	detail := hashes.ReasonCode
	if hashes.Detail != "" {
		if detail != "" {
			detail += ": "
		}
		detail += hashes.Detail
	}
	observation.Warnings = append(
		observation.Warnings,
		records.ObservationWarning{
			Code:   "ContentHashFailed",
			Detail: detail,
		},
	)

	// ReplacedDuringCollection is a stronger path/object state and already
	// prevents Complete from being claimed. All other statuses become Partial
	// when the integrated content observation failed.
	if observation.ObservationStatus != records.ObservationReplacedDuringCollection {
		observation.ObservationStatus = records.ObservationPartial
	}

	sort.Slice(observation.Warnings, func(i, j int) bool {
		return observation.Warnings[i].Code < observation.Warnings[j].Code
	})
}

// CollectPathStructural is a diagnostic-only structural collection entry point.
// It preserves the original minimal NTFS observation behavior and does not read
// file content. Production full observations use CollectPath, which includes
// integrated content hashes before returning.
func CollectPathStructural(
	ctx context.Context,
	scopeID string,
	governedRoot string,
	targetPath string,
) (Observation, error) {
	rootUnits, err := syscall.UTF16FromString(governedRoot)
	if err != nil {
		return Observation{}, &Error{Stage: StageValidatePath, Op: "UTF16FromString(GovernedRoot)", Err: err}
	}
	targetUnits, err := syscall.UTF16FromString(targetPath)
	if err != nil {
		return Observation{}, &Error{Stage: StageValidatePath, Op: "UTF16FromString(Target)", Err: err}
	}
	return collectUTF16Structural(
		ctx,
		scopeID,
		rootUnits[:len(rootUnits)-1],
		targetUnits[:len(targetUnits)-1],
	)
}

func collectUTF16Structural(
	ctx context.Context,
	scopeID string,
	governedRoot []uint16,
	targetPath []uint16,
) (Observation, error) {
	if scopeID == "" {
		return Observation{}, &Error{Stage: StageGovernedRoot, Op: "ValidateScope", Err: ErrScopeRequired}
	}
	if err := validateContext(ctx); err != nil {
		return Observation{}, err
	}
	if err := validateLocalAbsolutePath(governedRoot); err != nil {
		return Observation{}, &Error{Stage: StageGovernedRoot, Op: "ValidatePath", Err: err}
	}
	if err := validateLocalAbsolutePath(targetPath); err != nil {
		return Observation{}, &Error{Stage: StageValidatePath, Op: "ValidatePath", Err: err}
	}

	root, err := openGovernedRoot(scopeID, governedRoot)
	if err != nil {
		return Observation{}, err
	}
	defer syscall.CloseHandle(root.handle)

	targetHandle, err := openPath(nulTerminate(targetPath))
	if err != nil {
		return Observation{}, &Error{Stage: StageOpen, Op: "CreateFileW", Err: err}
	}
	defer syscall.CloseHandle(targetHandle)

	return collectOpenedTarget(ctx, root, CollectionEntryPath, targetPath, targetHandle, nil)
}
