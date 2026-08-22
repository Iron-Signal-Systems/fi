// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

// collectParentBinding records the parent directory for the observed pathname.
// It proves the relationship with handle-derived normalized paths rather than
// assuming that the caller's lexical parent remained authoritative.
func collectParentBinding(
	root governedRootContext,
	targetPath []uint16,
	targetFinalPath []uint16,
	targetState nativeState,
) (records.ParentObjectBinding, error) {
	if root.state.ID == targetState.ID {
		return records.ParentObjectBinding{State: records.ParentBindingGovernedRoot}, nil
	}

	callerParent, err := parentLocalAbsolutePath(targetPath)
	if err != nil {
		return records.ParentObjectBinding{}, err
	}
	parentHandle, err := openPath(nulTerminate(callerParent))
	if err != nil {
		return records.ParentObjectBinding{}, fmt.Errorf("open parent: %w", err)
	}
	defer syscall.CloseHandle(parentHandle)

	fileSystem, err := queryVolume(parentHandle)
	if err != nil {
		return records.ParentObjectBinding{}, fmt.Errorf("query parent volume: %w", err)
	}
	if !strings.EqualFold(fileSystem, "NTFS") {
		return records.ParentObjectBinding{}, ErrNotNTFS
	}

	parentState, err := queryNativeState(parentHandle)
	if err != nil {
		return records.ParentObjectBinding{}, err
	}
	if parentState.Standard.Directory == 0 && parentState.Basic.FileAttributes&fileAttributeDirectory == 0 {
		return records.ParentObjectBinding{}, fmt.Errorf("parent path is not a directory")
	}

	parentFinalPath, err := finalVolumePath(parentHandle)
	if err != nil {
		return records.ParentObjectBinding{}, fmt.Errorf("resolve parent path: %w", err)
	}
	parentVolumeGUID, err := volumeGUIDFromFinalPath(parentFinalPath)
	if err != nil {
		return records.ParentObjectBinding{}, err
	}
	if parentVolumeGUID != root.volumeGUID {
		return records.ParentObjectBinding{}, ErrOutsideGovernedRoot
	}

	expectedParent, err := directParentVolumePath(targetFinalPath)
	if err != nil {
		return records.ParentObjectBinding{}, err
	}
	if !equalUTF16(parentFinalPath, expectedParent) {
		return records.ParentObjectBinding{}, fmt.Errorf("parent handle does not match target handle parent")
	}

	_, parentIdentity, err := buildObjectIdentity(
		parentState.ID.VolumeSerialNumber,
		parentState.ID.FileID,
	)
	if err != nil {
		return records.ParentObjectBinding{}, err
	}
	return records.ParentObjectBindingFor(parentIdentity), nil
}

// directParentVolumePath returns the handle-derived parent of a normalized
// volume-GUID path. The volume root is preserved with its trailing separator.
func directParentVolumePath(path []uint16) ([]uint16, error) {
	rootLength, err := volumeRootLength(path)
	if err != nil {
		return nil, err
	}

	end := len(path)
	for end > rootLength && path[end-1] == '\\' {
		end--
	}
	if end <= rootLength {
		return append([]uint16(nil), path[:rootLength]...), nil
	}
	for index := end - 1; index >= rootLength; index-- {
		if path[index] == '\\' {
			return append([]uint16(nil), path[:index]...), nil
		}
	}
	return append([]uint16(nil), path[:rootLength]...), nil
}

func volumeRootLength(path []uint16) (int, error) {
	if !hasASCIIPrefix(path, `\\?\Volume{`) {
		return 0, ErrNotLocalVolume
	}
	for index := len(`\\?\Volume{`); index+1 < len(path); index++ {
		if path[index] == '}' && path[index+1] == '\\' {
			return index + 2, nil
		}
	}
	return 0, fmt.Errorf("volume GUID terminator missing")
}
