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
	if err := revalidateObservationAfterContent(ctx, root, targetHandle, &observation); err != nil {
		return Observation{}, err
	}
	sort.Slice(observation.Warnings, func(i, j int) bool {
		return observation.Warnings[i].Code < observation.Warnings[j].Code
	})
	observation.ObservedAt = time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")
	if err := ValidateObservation(observation); err != nil {
		return Observation{}, &Error{Stage: StageMetadata, Op: "ValidateObservationWithContentHashes", Err: err}
	}
	return observation, nil
}

// revalidateObservationAfterContent closes the interval between structural
// acceptance and completion of content collection. The original target handle
// remains open for this check. FI re-reads native state, re-proves governed-root
// scope, and verifies that the accepted handle-derived path still represents the
// same namespace binding before the whole observation can remain Complete.
func revalidateObservationAfterContent(
	ctx context.Context,
	root governedRootContext,
	targetHandle syscall.Handle,
	observation *Observation,
) error {
	if observation == nil {
		return &Error{Stage: StageConsistency, Op: "RevalidateAfterContent", Err: ErrIdentityChanged}
	}
	if err := validateContext(ctx); err != nil {
		return err
	}

	finalState, err := queryNativeState(targetHandle)
	if err != nil {
		return err
	}
	_, finalIdentity, err := buildObjectIdentity(finalState.ID.VolumeSerialNumber, finalState.ID.FileID)
	if err != nil {
		return &Error{Stage: StageIdentity, Op: "DecodePostContentNTFSFileID", Err: err}
	}
	if finalIdentity != observation.ObjectIdentity {
		return &Error{Stage: StageConsistency, Op: "PostContentIdentity", Err: ErrIdentityChanged}
	}

	if reparseObservationChanged(observation.Reparse, finalState.AttributeTag) {
		return &Error{Stage: StageConsistency, Op: "PostContentReparseState", Err: ErrReparseChangedDuringCollection}
	}

	metadataChanged, err := observationRelevantNativeStateChanged(*observation, finalState)
	if err != nil {
		return &Error{Stage: StageMetadata, Op: "PostContentMetadata", Err: err}
	}
	if metadataChanged {
		appendObservationWarningOnce(observation, records.ObservationWarning{Code: "MetadataChangedDuringCollection"})
		switch observation.ObservationStatus {
		case records.ObservationComplete:
			observation.ObservationStatus = records.ObservationChangedDuringCollection
		case records.ObservationChangedDuringCollection,
			records.ObservationPartial,
			records.ObservationReplacedDuringCollection:
		}
	}

	finalPath, err := revalidateScopeHandles(
		root.handle,
		targetHandle,
		root.requestedPath,
		root.finalPath,
		root.state.ID,
		finalState.ID,
	)
	if err != nil {
		return &Error{Stage: StageConsistency, Op: "RevalidateGovernedScopeAfterContent", Err: err}
	}
	if utf16LEBase64URL(finalPath) != observation.PathBinding.ResolvedPathUTF16LEBase64URL {
		appendObservationWarningOnce(observation, records.ObservationWarning{
			Code:   "PathConsistencyNotVerified",
			Detail: "target handle resolved path changed after structural collection",
		})
		if observation.ObservationStatus != records.ObservationReplacedDuringCollection {
			observation.ObservationStatus = records.ObservationPartial
		}
	}

	return validateContext(ctx)
}

func appendObservationWarningOnce(observation *Observation, warning records.ObservationWarning) {
	if observation == nil || warning.Code == "" {
		return
	}
	for _, current := range observation.Warnings {
		if current.Code == warning.Code {
			return
		}
	}
	observation.Warnings = append(observation.Warnings, warning)
}

func observationRelevantNativeStateChanged(observation Observation, state nativeState) (bool, error) {
	metadata, subjectKind, err := metadataFromState(state)
	if err != nil {
		return false, err
	}
	if subjectKind != observation.SubjectKind {
		return true, nil
	}

	return observation.Metadata.LogicalSize != metadata.LogicalSize ||
		observation.Metadata.AllocatedSize != metadata.AllocatedSize ||
		observation.Metadata.CreationTime != metadata.CreationTime ||
		observation.Metadata.LastWriteTime != metadata.LastWriteTime ||
		observation.Metadata.ChangeTime != metadata.ChangeTime ||
		observation.Metadata.RawAttributes != metadata.RawAttributes ||
		observation.Metadata.LinkCount != metadata.LinkCount, nil
}

func reparseObservationChanged(observation records.ReparseObservation, state fileAttributeTagInfo) bool {
	present := state.FileAttributes&fileAttributeReparse != 0
	switch observation.State {
	case records.ReparseStateNotPresent:
		return present
	case records.ReparseStatePresent:
		return !present || observation.Tag != reparseTagString(state.ReparseTag)
	default:
		return true
	}
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
