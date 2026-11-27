// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"os"
	"syscall"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

// verifyWalkDirectoryIdentity runs after os.Open and before the first ReadDir.
// It prevents traversal when the pathname was rebound to another object (or the
// observed directory moved) between CollectPath and directory enumeration.
func verifyWalkDirectoryIdentity(directory *os.File, expected Observation) error {
	state, err := queryNativeState(syscall.Handle(directory.Fd()))
	if err != nil {
		return err
	}
	if state.Standard.Directory == 0 && state.Basic.FileAttributes&fileAttributeDirectory == 0 {
		return ErrWalkDirectoryChanged
	}
	if state.Basic.FileAttributes&fileAttributeReparse != 0 {
		return ErrWalkDirectoryChanged
	}

	volumeIdentity, objectIdentity, err := buildObjectIdentity(state.ID.VolumeSerialNumber, state.ID.FileID)
	if err != nil {
		return err
	}
	finalPath, err := finalVolumePath(syscall.Handle(directory.Fd()))
	if err != nil {
		return err
	}
	volumeGUID, err := volumeGUIDFromFinalPath(finalPath)
	if err != nil {
		return err
	}
	volumeIdentity.VolumeGUID = volumeGUID

	if volumeIdentity != expected.VolumeIdentity || objectIdentity != expected.ObjectIdentity {
		return ErrWalkDirectoryChanged
	}
	if utf16LEBase64URL(finalPath) != expected.PathBinding.ResolvedPathUTF16LEBase64URL {
		return ErrWalkDirectoryChanged
	}
	if expected.SubjectKind != records.SubjectDirectory || expected.Reparse.State == records.ReparseStatePresent {
		return ErrWalkDirectoryChanged
	}
	return nil
}
