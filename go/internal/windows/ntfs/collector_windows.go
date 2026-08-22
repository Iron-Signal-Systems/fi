// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"context"
	"strings"
	"syscall"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

// governedRootContext is the already-open, already-proven governed-root state
// shared by collection entry points. Keeping the root handle open lets the
// collection core reason from handles instead of reopening/trusting text paths.
type governedRootContext struct {
	scopeID        string
	requestedPath  []uint16
	handle         syscall.Handle
	state          nativeState
	finalPath      []uint16
	volumeGUID     string
	volumeIdentity records.VolumeIdentity
	objectIdentity records.NTFSObjectIdentity
}

// CollectPath collects one governed local NTFS object.
//
// governedRoot is the authorized collection boundary and must resolve to a
// non-reparse NTFS directory. targetPath must identify the base NTFS object
// inside that root; named-stream paths are rejected because FI enumerates
// ADS/streams from the opened base object.
//
// The function returns a complete or explicitly partial Observation. Fatal
// failures return an error instead of manufacturing a successful record.
func CollectPath(ctx context.Context, scopeID string, governedRoot string, targetPath string) (Observation, error) {
	rootUnits, err := syscall.UTF16FromString(governedRoot)
	if err != nil {
		return Observation{}, &Error{Stage: StageValidatePath, Op: "UTF16FromString(GovernedRoot)", Err: err}
	}
	targetUnits, err := syscall.UTF16FromString(targetPath)
	if err != nil {
		return Observation{}, &Error{Stage: StageValidatePath, Op: "UTF16FromString(Target)", Err: err}
	}

	// UTF16FromString includes the terminating NUL. CollectUTF16 works with the
	// path itself and adds a NUL only when calling Windows.
	return CollectUTF16(
		ctx,
		scopeID,
		rootUnits[:len(rootUnits)-1],
		targetUnits[:len(targetUnits)-1],
	)
}

// CollectUTF16 validates caller paths, opens the governed root and target, and
// then delegates the actual NTFS observation to collectOpenedTarget.
//
// The split is deliberate: future change-feed collection can open an object by
// NTFS file ID and reuse the same opened-handle observation core instead of
// creating a second NTFS collector.
func CollectUTF16(ctx context.Context, scopeID string, governedRoot []uint16, targetPath []uint16) (Observation, error) {
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

	return collectOpenedTarget(ctx, root, targetPath, targetHandle)
}

func openGovernedRoot(scopeID string, governedRoot []uint16) (governedRootContext, error) {
	rootHandle, err := openPath(nulTerminate(governedRoot))
	if err != nil {
		return governedRootContext{}, &Error{Stage: StageGovernedRoot, Op: "CreateFileW", Err: err}
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			syscall.CloseHandle(rootHandle)
		}
	}()

	rootFileSystem, err := queryVolume(rootHandle)
	if err != nil {
		return governedRootContext{}, &Error{Stage: StageGovernedRoot, Op: "GetVolumeInformationByHandleW", Err: err}
	}
	if !strings.EqualFold(rootFileSystem, "NTFS") {
		return governedRootContext{}, &Error{Stage: StageGovernedRoot, Op: "VerifyNTFS", Err: ErrNotNTFS}
	}

	rootState, err := queryNativeState(rootHandle)
	if err != nil {
		return governedRootContext{}, err
	}
	if rootState.Standard.Directory == 0 && rootState.Basic.FileAttributes&fileAttributeDirectory == 0 {
		return governedRootContext{}, &Error{Stage: StageGovernedRoot, Op: "VerifyDirectory", Err: ErrGovernedRootNotDirectory}
	}
	if rootState.Basic.FileAttributes&fileAttributeReparse != 0 {
		return governedRootContext{}, &Error{Stage: StageGovernedRoot, Op: "RejectReparseRoot", Err: ErrGovernedRootReparse}
	}

	rootFinalPath, err := finalVolumePath(rootHandle)
	if err != nil {
		return governedRootContext{}, &Error{Stage: StageGovernedRoot, Op: "GetFinalPathNameByHandleW", Err: err}
	}
	rootVolumeGUID, err := volumeGUIDFromFinalPath(rootFinalPath)
	if err != nil {
		return governedRootContext{}, &Error{Stage: StageGovernedRoot, Op: "ParseVolumeGUID", Err: err}
	}

	rootVolumeIdentity, rootObjectIdentity, err := buildObjectIdentity(
		rootState.ID.VolumeSerialNumber,
		rootState.ID.FileID,
	)
	if err != nil {
		return governedRootContext{}, &Error{Stage: StageGovernedRoot, Op: "DecodeNTFSFileID", Err: err}
	}
	rootVolumeIdentity.VolumeGUID = rootVolumeGUID

	closeOnError = false
	return governedRootContext{
		scopeID:        scopeID,
		requestedPath:  append([]uint16(nil), governedRoot...),
		handle:         rootHandle,
		state:          rootState,
		finalPath:      rootFinalPath,
		volumeGUID:     rootVolumeGUID,
		volumeIdentity: rootVolumeIdentity,
		objectIdentity: rootObjectIdentity,
	}, nil
}

func validateContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func nulTerminate(path []uint16) []uint16 {
	return append(append([]uint16(nil), path...), 0)
}
