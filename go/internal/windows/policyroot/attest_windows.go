// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package policyroot

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/policyassociation"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumediscovery"
	"golang.org/x/sys/windows"
)

const rootFileIDInfoClass = 18 // FILE_INFO_BY_HANDLE_CLASS.FileIdInfo

var (
	rootKernel32            = windows.NewLazySystemDLL("kernel32.dll")
	procRootFileInformation = rootKernel32.NewProc("GetFileInformationByHandleEx")
	ErrUnattestedRoot       = errors.New("FI v2 governed-root native identity cannot be attested")
)

type nativeDirectoryIdentity struct {
	VolumeSerial uint64
	FileID       policyassociation.FileID
}

// FILE_ID_INFO: full-width volume serial and FILE_ID_128. Refuse ABI drift.
var (
	_ [24 - unsafe.Sizeof(nativeDirectoryIdentity{})]byte
	_ [unsafe.Sizeof(nativeDirectoryIdentity{}) - 24]byte
)

// AttestEnrolledVolumeRoots observes the native object IDs for the selected
// volume's policy roots. It requires independently supplied CONFIG but does
// NOT authenticate that configuration or authorize a privileged operation.
// A future verified installed grant and fresh re-attestation are mandatory.
func AttestEnrolledVolumeRoots(
	ctx context.Context,
	scope config.VolumeConfig,
	enrollmentID string,
) ([]policyassociation.RootBinding, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context required", ErrUnattestedRoot)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	selected, targets, err := targetsForVolume(scope, enrollmentID)
	if err != nil {
		return nil, err
	}
	native, err := volumediscovery.Enumerate(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: enumerate local NTFS volumes: %v", ErrUnattestedRoot, err)
	}
	preflight, err := volumediscovery.AssessEnrollment(scope, native)
	if err != nil {
		return nil, fmt.Errorf("%w: inconsistent native volume inventory: %v", ErrUnattestedRoot, err)
	}
	// Other enrolled volumes may be offline: do not let that prevent an
	// independently healthy selected volume from being observed.
	matched := false
	for _, entry := range preflight.Matches {
		if entry.EnrollmentID == enrollmentID {
			matched = entry.Status == volumediscovery.IdentityMatched
			break
		}
	}
	if !matched {
		return nil, fmt.Errorf("%w: selected volume %q identity is not currently matched", ErrUnattestedRoot, enrollmentID)
	}
	if len(targets) == 0 {
		return []policyassociation.RootBinding{}, nil
	}
	serial, err := strconv.ParseUint(selected.Serial, 10, 64)
	if err != nil || serial == 0 {
		return nil, fmt.Errorf("%w: invalid full-width volume serial", ErrUnattestedRoot)
	}
	out := make([]policyassociation.RootBinding, 0, len(targets))
	for _, item := range targets {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		paths, err := rootWalkPaths(item)
		if err != nil {
			return nil, err
		}
		id, err := attestNativeDirectoryChain(ctx, paths, serial)
		if err != nil {
			// No partial binding list may silently drop an unresolved policy.
			return nil, fmt.Errorf("%w: policy %q: %v", ErrUnattestedRoot, item.policyID, err)
		}
		out = append(out, policyassociation.RootBinding{
			PolicyID: item.policyID, VolumeID: item.volumeID, RootID: id,
		})
	}
	return out, nil
}

// attestNativeDirectoryChain retains every ancestor handle while inspecting
// its immediate child. Denying FILE_SHARE_DELETE blocks rename/substitution
// of held directories; OPEN_REPARSE_POINT prevents following the final
// component before its type is examined. Every opened directory must report
// the same approved full-width NTFS serial via FILE_ID_INFO.
//
// This read-only observation cannot authorize any later file access: the
// handles close before returning, and the namespace may subsequently change.
func attestNativeDirectoryChain(
	ctx context.Context,
	paths []string,
	expectedSerial uint64,
) (policyassociation.FileID, error) {
	if ctx == nil || expectedSerial == 0 || len(paths) == 0 ||
		len(paths) > maxRootWalkComponents+1 {
		return policyassociation.FileID{}, fmt.Errorf("%w: missing or unbounded native walk inputs", ErrUnattestedRoot)
	}
	held := make([]windows.Handle, 0, len(paths))
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			_ = windows.CloseHandle(held[i])
		}
	}()
	var id policyassociation.FileID
	for index, path := range paths {
		if err := ctx.Err(); err != nil {
			return policyassociation.FileID{}, err
		}
		if index > 0 {
			parent := strings.TrimSuffix(paths[index-1], `\`)
			prefix := parent + `\`
			if len(path) <= len(prefix) ||
				!strings.EqualFold(path[:len(prefix)], prefix) ||
				strings.ContainsAny(path[len(prefix):], `\/`) ||
				path[len(prefix):] == "." || path[len(prefix):] == ".." {
				return policyassociation.FileID{}, fmt.Errorf("%w: substituted or skipped parent directory", ErrUnattestedRoot)
			}
		}
		ptr, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return policyassociation.FileID{}, fmt.Errorf("%w: invalid native path encoding: %v", ErrUnattestedRoot, err)
		}
		h, err := windows.CreateFile(
			ptr, windows.FILE_READ_ATTRIBUTES,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, // deliberately deny delete/rename
			nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0,
		)
		if err != nil {
			return policyassociation.FileID{}, fmt.Errorf("%w: open native directory component %d: %v", ErrUnattestedRoot, index, err)
		}
		held = append(held, h)
		var attributes windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(h, &attributes); err != nil {
			return policyassociation.FileID{}, fmt.Errorf("%w: inspect native component %d: %v", ErrUnattestedRoot, index, err)
		}
		if attributes.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 ||
			attributes.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return policyassociation.FileID{}, fmt.Errorf("%w: component %d is not a plain directory", ErrUnattestedRoot, index)
		}
		native, err := queryNativeDirectoryIdentity(h)
		if err != nil {
			return policyassociation.FileID{}, err
		}
		if native.VolumeSerial != expectedSerial {
			return policyassociation.FileID{}, fmt.Errorf("%w: component %d full-width volume serial mismatch", ErrUnattestedRoot, index)
		}
		id = native.FileID
	}
	return id, nil
}

func queryNativeDirectoryIdentity(handle windows.Handle) (nativeDirectoryIdentity, error) {
	if handle == 0 || handle == windows.InvalidHandle {
		return nativeDirectoryIdentity{}, fmt.Errorf("%w: invalid native directory handle", ErrUnattestedRoot)
	}
	var info nativeDirectoryIdentity
	ok, _, callErr := procRootFileInformation.Call(
		uintptr(handle), rootFileIDInfoClass,
		uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info),
	)
	if ok == 0 {
		return nativeDirectoryIdentity{}, fmt.Errorf("%w: GetFileInformationByHandleEx(FileIdInfo): %v", ErrUnattestedRoot, callErr)
	}
	if info.VolumeSerial == 0 || info.FileID == (policyassociation.FileID{}) {
		return nativeDirectoryIdentity{}, fmt.Errorf("%w: zero native NTFS serial or file ID", ErrUnattestedRoot)
	}
	return info, nil
}
