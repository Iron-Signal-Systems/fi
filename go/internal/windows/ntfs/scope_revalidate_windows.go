// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"fmt"
	"syscall"
)

// revalidateScopeHandles proves immediately before observation acceptance that:
//   - the original governed-root handle still identifies the same non-reparse directory;
//   - that handle still resolves to the same volume-GUID path;
//   - reopening the configured governed-root path still reaches that same object;
//   - the target handle still identifies the collected object; and
//   - the target's current handle-derived path is still contained by that root.
//
// This closes the common namespace-substitution window without trusting cached
// caller path strings at the final acceptance boundary.
func revalidateScopeHandles(
	rootHandle syscall.Handle,
	targetHandle syscall.Handle,
	governedRoot []uint16,
	expectedRootFinalPath []uint16,
	expectedRootID fileIDInfo,
	expectedTargetID fileIDInfo,
) ([]uint16, error) {
	rootState, err := queryNativeState(rootHandle)
	if err != nil {
		return nil, err
	}
	if rootState.ID != expectedRootID ||
		(rootState.Standard.Directory == 0 && rootState.Basic.FileAttributes&fileAttributeDirectory == 0) ||
		rootState.Basic.FileAttributes&fileAttributeReparse != 0 {
		return nil, ErrGovernedRootChangedDuringCollection
	}

	rootFinalPath, err := finalVolumePath(rootHandle)
	if err != nil {
		return nil, err
	}
	if !equalUTF16(rootFinalPath, expectedRootFinalPath) {
		return nil, ErrGovernedRootChangedDuringCollection
	}
	rootVolumeGUID, err := volumeGUIDFromFinalPath(rootFinalPath)
	if err != nil {
		return nil, err
	}

	targetState, err := queryNativeState(targetHandle)
	if err != nil {
		return nil, err
	}
	if targetState.ID != expectedTargetID {
		return nil, ErrIdentityChanged
	}
	targetFinalPath, err := finalVolumePath(targetHandle)
	if err != nil {
		return nil, err
	}
	targetVolumeGUID, err := volumeGUIDFromFinalPath(targetFinalPath)
	if err != nil {
		return nil, err
	}
	if targetVolumeGUID != rootVolumeGUID || !pathContainedBy(rootFinalPath, targetFinalPath) {
		return nil, ErrOutsideGovernedRoot
	}

	reopened, err := openPath(nulTerminate(governedRoot))
	if err != nil {
		return nil, fmt.Errorf("%w: reopen governed root: %v", ErrGovernedRootChangedDuringCollection, err)
	}
	defer syscall.CloseHandle(reopened)

	reopenedState, stateErr := queryNativeState(reopened)
	reopenedFinalPath, pathErr := finalVolumePath(reopened)
	if stateErr != nil || pathErr != nil {
		return nil, ErrGovernedRootChangedDuringCollection
	}
	if reopenedState.ID != expectedRootID ||
		(reopenedState.Standard.Directory == 0 && reopenedState.Basic.FileAttributes&fileAttributeDirectory == 0) ||
		reopenedState.Basic.FileAttributes&fileAttributeReparse != 0 ||
		!equalUTF16(reopenedFinalPath, expectedRootFinalPath) {
		return nil, ErrGovernedRootChangedDuringCollection
	}

	return targetFinalPath, nil
}
