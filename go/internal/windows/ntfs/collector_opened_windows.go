// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

// collectOpenedTarget performs the NTFS observation against an already-open
// target handle. The caller owns targetHandle and the governed-root handle.
//
// entryMethod records how the initial target handle was obtained. targetPath is
// required for path entry and nil for NTFSFileID entry. ID-opened collection
// derives the current path from the handle, then uses that path only for
// namespace consistency checks and the observed PathBinding.
func collectOpenedTarget(
	ctx context.Context,
	root governedRootContext,
	entryMethod CollectionEntryMethod,
	targetPath []uint16,
	targetHandle syscall.Handle,
	expectedIdentity *records.NTFSObjectIdentity,
) (Observation, error) {
	if err := validateContext(ctx); err != nil {
		return Observation{}, err
	}

	targetFileSystem, err := queryVolume(targetHandle)
	if err != nil {
		return Observation{}, &Error{Stage: StageVolume, Op: "GetVolumeInformationByHandleW", Err: err}
	}
	if !strings.EqualFold(targetFileSystem, "NTFS") {
		return Observation{}, &Error{Stage: StageVolume, Op: "VerifyNTFS", Err: ErrNotNTFS}
	}

	targetFinalPath, err := finalVolumePath(targetHandle)
	if err != nil {
		return Observation{}, &Error{Stage: StageContainment, Op: "GetFinalPathNameByHandleW", Err: err}
	}
	targetVolumeGUID, err := volumeGUIDFromFinalPath(targetFinalPath)
	if err != nil {
		return Observation{}, &Error{Stage: StageContainment, Op: "ParseVolumeGUID", Err: err}
	}
	if targetVolumeGUID != root.volumeGUID || !pathContainedBy(root.finalPath, targetFinalPath) {
		return Observation{}, &Error{Stage: StageContainment, Op: "HandleDerivedContainment", Err: ErrOutsideGovernedRoot}
	}

	pre, err := queryNativeState(targetHandle)
	if err != nil {
		return Observation{}, err
	}
	if expectedIdentity != nil {
		_, openedIdentity, identityErr := buildObjectIdentity(pre.ID.VolumeSerialNumber, pre.ID.FileID)
		if identityErr != nil {
			return Observation{}, &Error{Stage: StageIdentity, Op: "DecodeOpenedNTFSFileID", Err: identityErr}
		}
		if openedIdentity != *expectedIdentity {
			return Observation{}, &Error{Stage: StageIdentity, Op: "VerifyOpenFileByIdIdentity", Err: ErrObjectIdentityMismatch}
		}
	}

	switch entryMethod {
	case CollectionEntryPath:
		if len(targetPath) == 0 {
			return Observation{}, &Error{Stage: StageValidatePath, Op: "ValidateEntryPath", Err: ErrInvalidPath}
		}
	case CollectionEntryNTFSFileID:
		// The ID open has no caller target path. Use the handle-resolved current
		// path for the namespace consistency check and PathBinding record.
		targetPath = append([]uint16(nil), targetFinalPath...)
	default:
		return Observation{}, &Error{Stage: StageOpen, Op: "ValidateCollectionEntryMethod", Err: fmt.Errorf("unsupported collection entry method %q", entryMethod)}
	}

	streamInventory := records.StreamInventory{
		State:   records.ObservationStatePresent,
		Streams: []records.StreamObservation{},
	}
	warnings := []records.ObservationWarning{}
	status := records.ObservationComplete

	nativeStreams, streamErr := queryStreams(targetHandle)
	if streamErr != nil {
		streamInventory = records.StreamInventory{
			State:      records.ObservationStateError,
			Streams:    []records.StreamObservation{},
			ReasonCode: "StreamEnumerationFailed",
		}
		status = records.ObservationPartial
		warnings = append(warnings, records.ObservationWarning{
			Code:   "StreamEnumerationFailed",
			Detail: streamErr.Error(),
		})
	} else {
		streamInventory.Streams, err = streamObservations(nativeStreams)
		if err != nil {
			return Observation{}, &Error{Stage: StageStreams, Op: "Convert", Err: err}
		}
	}

	var security records.SecurityObservation
	rawSecurity, securityErr := querySecurityDescriptor(targetHandle)
	if securityErr != nil {
		security = records.SecurityObservationError("SecurityDescriptorReadFailed")
		status = records.ObservationPartial
		warnings = append(warnings, records.ObservationWarning{
			Code:   "SecurityDescriptorReadFailed",
			Detail: securityErr.Error(),
		})
	} else {
		parsedSecurity, parseErr := records.ParseSecurityDescriptor(rawSecurity)
		if parseErr != nil {
			security = records.RawSecurityObservation(rawSecurity, "SecurityDescriptorParseFailed")
			status = records.ObservationPartial
			warnings = append(warnings, records.ObservationWarning{
				Code:   "SecurityDescriptorParseFailed",
				Detail: parseErr.Error(),
			})
		} else {
			security = parsedSecurity
		}
	}

	var sacl records.SACLObservation
	rawSACL, saclErr := querySACLDescriptor(targetHandle)
	if saclErr != nil {
		reasonCode := saclQueryReasonCode(saclErr)
		sacl = records.SACLObservationError(reasonCode)
		status = records.ObservationPartial
		warnings = append(warnings, records.ObservationWarning{
			Code:   reasonCode,
			Detail: saclErr.Error(),
		})
	} else {
		parsedSACL, parseErr := records.ParseSACLDescriptor(rawSACL)
		if parseErr != nil {
			sacl = records.RawSACLObservation(rawSACL, "SACLDescriptorParseFailed")
			status = records.ObservationPartial
			warnings = append(warnings, records.ObservationWarning{
				Code:   "SACLDescriptorParseFailed",
				Detail: parseErr.Error(),
			})
		} else {
			sacl = parsedSACL
		}
	}

	mid, err := queryNativeState(targetHandle)
	if err != nil {
		return Observation{}, err
	}
	if pre.ID != mid.ID {
		return Observation{}, &Error{Stage: StageConsistency, Op: "SameHandleIdentity", Err: ErrIdentityChanged}
	}

	reparse := reparseObservationNotPresent()
	if mid.AttributeTag.FileAttributes&fileAttributeReparse != 0 {
		rawReparse, reparseErr := queryReparseData(targetHandle)
		if reparseErr != nil {
			reparse = reparseObservationError(mid.AttributeTag.ReparseTag, "ReparseDataReadFailed")
			status = records.ObservationPartial
			warnings = append(warnings, records.ObservationWarning{
				Code:   "ReparseDataReadFailed",
				Detail: reparseErr.Error(),
			})
		} else {
			parsedReparse, parseErr := parseReparseData(rawReparse)
			if parseErr != nil {
				reparse = reparseObservationRaw(mid.AttributeTag.ReparseTag, rawReparse, "ReparseDataParseFailed")
				status = records.ObservationPartial
				warnings = append(warnings, records.ObservationWarning{
					Code:   "ReparseDataParseFailed",
					Detail: parseErr.Error(),
				})
			} else {
				if parsedReparse.Tag != mid.AttributeTag.ReparseTag {
					return Observation{}, &Error{Stage: StageConsistency, Op: "ReparseTagConsistency", Err: ErrReparseChangedDuringCollection}
				}
				reparse = reparseObservationParsed(parsedReparse)
			}
		}
	}

	post, err := queryNativeState(targetHandle)
	if err != nil {
		return Observation{}, err
	}
	if mid.ID != post.ID {
		return Observation{}, &Error{Stage: StageConsistency, Op: "SameHandleIdentity", Err: ErrIdentityChanged}
	}
	if reparseStateChanged(mid.AttributeTag, post.AttributeTag) {
		return Observation{}, &Error{Stage: StageConsistency, Op: "ReparseStateConsistency", Err: ErrReparseChangedDuringCollection}
	}

	volumeIdentity, objectIdentity, err := buildObjectIdentity(
		post.ID.VolumeSerialNumber,
		post.ID.FileID,
	)
	if err != nil {
		return Observation{}, &Error{Stage: StageIdentity, Op: "DecodeNTFSFileID", Err: err}
	}
	volumeIdentity.VolumeGUID = targetVolumeGUID

	metadata, subjectKind, err := metadataFromState(post)
	if err != nil {
		return Observation{}, &Error{Stage: StageMetadata, Op: "Convert", Err: err}
	}

	if pre.AttributeTag != post.AttributeTag || pre.Basic != post.Basic || pre.Standard != post.Standard {
		if status == records.ObservationComplete {
			status = records.ObservationChangedDuringCollection
		} else {
			status = records.ObservationPartial
		}
		warnings = append(warnings, records.ObservationWarning{
			Code: "MetadataChangedDuringCollection",
		})
	}

	reopened, reopenErr := openPath(nulTerminate(targetPath))
	if reopenErr != nil {
		status = records.ObservationPartial
		warnings = append(warnings, records.ObservationWarning{
			Code: "PathConsistencyNotVerified",
		})
	} else {
		reopenedFinalPath, finalErr := finalVolumePath(reopened)
		reopenedState, stateErr := queryNativeState(reopened)
		syscall.CloseHandle(reopened)

		if finalErr != nil || stateErr != nil {
			status = records.ObservationPartial
			warnings = append(warnings, records.ObservationWarning{
				Code: "PathConsistencyNotVerified",
			})
		} else if !pathContainedBy(root.finalPath, reopenedFinalPath) {
			return Observation{}, &Error{Stage: StageContainment, Op: "ReopenContainment", Err: ErrOutsideGovernedRoot}
		} else if reopenedState.ID != post.ID {
			status = records.ObservationReplacedDuringCollection
			warnings = append(warnings, records.ObservationWarning{
				Code: "PathNowReferencesDifferentObject",
			})
		}
	}

	// Re-prove the root object/path binding and current target containment at the
	// final acceptance boundary. This does not trust the root path snapshot taken
	// at the beginning of collection.
	finalTargetPath, err := revalidateScopeHandles(
		root.handle,
		targetHandle,
		root.requestedPath,
		root.finalPath,
		root.state.ID,
		post.ID,
	)
	if err != nil {
		return Observation{}, &Error{Stage: StageConsistency, Op: "RevalidateGovernedScope", Err: err}
	}
	targetFinalPath = finalTargetPath
	targetVolumeGUID, err = volumeGUIDFromFinalPath(targetFinalPath)
	if err != nil {
		return Observation{}, &Error{Stage: StageConsistency, Op: "ParseFinalTargetVolumeGUID", Err: err}
	}
	volumeIdentity.VolumeGUID = targetVolumeGUID

	parentBinding, parentErr := collectParentBinding(root, targetFinalPath, post)
	if parentErr != nil {
		parentBinding = records.ParentObjectBindingError(parentBindingUnavailableReason)
		if status != records.ObservationReplacedDuringCollection {
			status = records.ObservationPartial
		}
		warnings = append(warnings, records.ObservationWarning{
			Code:   parentBindingUnavailableReason,
			Detail: parentErr.Error(),
		})
	}

	if err := validateContext(ctx); err != nil {
		return Observation{}, err
	}

	sort.Slice(warnings, func(i, j int) bool {
		return warnings[i].Code < warnings[j].Code
	})

	observedAt := time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z")

	observation := Observation{
		GovernedRoot: records.GovernedRootIdentity{
			ScopeID:                       root.scopeID,
			RequestedPathUTF16LEBase64URL: utf16LEBase64URL(root.requestedPath),
			ResolvedPathUTF16LEBase64URL:  utf16LEBase64URL(root.finalPath),
			MethodVersion:                 ContainmentMethodVersion,
			VolumeIdentity:                root.volumeIdentity,
			ObjectIdentity:                root.objectIdentity,
		},
		Containment: records.PathContainment{
			MethodVersion: ContainmentMethodVersion,
		},
		VolumeIdentity: volumeIdentity,
		ObjectIdentity: objectIdentity,
		ParentBinding:  parentBinding,
		SubjectKind:    subjectKind,
		PathBinding: records.PathBinding{
			RequestedPathUTF16LEBase64URL: utf16LEBase64URL(targetPath),
			ResolvedPathUTF16LEBase64URL:  utf16LEBase64URL(targetFinalPath),
		},
		ObservedAt:            observedAt,
		Metadata:              metadata,
		Security:              security,
		SACL:                  sacl,
		Reparse:               reparse,
		StreamInventory:       streamInventory,
		CollectionEntryMethod: entryMethod,
		CollectionMethod:      records.CollectionDirectWindowsNTFS,
		ObservationStatus:     status,
		Warnings:              warnings,
	}

	if err := ValidateObservation(observation); err != nil {
		return Observation{}, &Error{Stage: StageMetadata, Op: "ValidateObservation", Err: err}
	}
	return observation, nil
}

// metadataFromState converts the Windows basic/standard information returned
// for the open handle into the shared FI metadata representation.
func metadataFromState(state nativeState) (records.MetadataObservation, records.SubjectKind, error) {
	if state.Standard.EndOfFile < 0 || state.Standard.AllocationSize < 0 {
		return records.MetadataObservation{}, "", fmt.Errorf("negative file size")
	}

	creationTime, err := filetimeToCanonical(state.Basic.CreationTime)
	if err != nil {
		return records.MetadataObservation{}, "", err
	}
	lastAccessTime, err := filetimeToCanonical(state.Basic.LastAccessTime)
	if err != nil {
		return records.MetadataObservation{}, "", err
	}
	lastWriteTime, err := filetimeToCanonical(state.Basic.LastWriteTime)
	if err != nil {
		return records.MetadataObservation{}, "", err
	}
	changeTime, err := filetimeToCanonical(state.Basic.ChangeTime)
	if err != nil {
		return records.MetadataObservation{}, "", err
	}

	subjectKind := records.SubjectFile
	if state.Standard.Directory != 0 || state.Basic.FileAttributes&fileAttributeDirectory != 0 {
		subjectKind = records.SubjectDirectory
	}

	return records.MetadataObservation{
		LogicalSize:    strconv.FormatUint(uint64(state.Standard.EndOfFile), 10),
		AllocatedSize:  strconv.FormatUint(uint64(state.Standard.AllocationSize), 10),
		CreationTime:   creationTime,
		LastWriteTime:  lastWriteTime,
		ChangeTime:     changeTime,
		LastAccessTime: lastAccessTime,
		RawAttributes:  strconv.FormatUint(uint64(state.Basic.FileAttributes), 10),
		LinkCount:      strconv.FormatUint(uint64(state.Standard.NumberOfLinks), 10),
	}, subjectKind, nil
}

func reparseStateChanged(left, right fileAttributeTagInfo) bool {
	leftPresent := left.FileAttributes&fileAttributeReparse != 0
	rightPresent := right.FileAttributes&fileAttributeReparse != 0

	if leftPresent != rightPresent {
		return true
	}
	return leftPresent && left.ReparseTag != right.ReparseTag
}

// streamObservations converts Windows FILE_STREAM_INFO entries and sorts them
// by their preserved raw-name encoding so staged records are deterministic.
func streamObservations(native []nativeStream) ([]records.StreamObservation, error) {
	observations := make([]records.StreamObservation, 0, len(native))
	for _, stream := range native {
		if stream.Size < 0 || stream.AllocationSize < 0 {
			return nil, fmt.Errorf("negative stream size")
		}
		observations = append(observations, records.StreamObservation{
			Identity:      streamIdentityFromWindowsName(stream.Name),
			LogicalSize:   strconv.FormatUint(uint64(stream.Size), 10),
			AllocatedSize: strconv.FormatUint(uint64(stream.AllocationSize), 10),
		})
	}

	sort.Slice(observations, func(i, j int) bool {
		return observations[i].Identity.RawNameUTF16LEBase64URL <
			observations[j].Identity.RawNameUTF16LEBase64URL
	})
	return observations, nil
}
