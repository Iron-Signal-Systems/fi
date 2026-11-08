// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package volumediscovery

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	fileIDInfoClass     = 18 // FILE_INFO_BY_HANDLE_CLASS.FileIdInfo
	fileReadAttributes  = 0x0080
	maxVolumeNameUnits  = 1024
	maxMountPathUnits   = 65536
	maxDiscoveredVolumes = 1024 // discovery must have a bounded inventory
	errorNoMoreFiles    = syscall.Errno(18)
	errorMoreData       = syscall.Errno(234)
	errorBufferTooSmall = syscall.Errno(122)
)

var (
	volumeKernel32              = syscall.NewLazyDLL("kernel32.dll")
	procFindFirstVolumeW        = volumeKernel32.NewProc("FindFirstVolumeW")
	procFindNextVolumeW         = volumeKernel32.NewProc("FindNextVolumeW")
	procFindVolumeClose         = volumeKernel32.NewProc("FindVolumeClose")
	procGetVolumePathNamesW     = volumeKernel32.NewProc("GetVolumePathNamesForVolumeNameW")
	procGetVolumeInformationW   = volumeKernel32.NewProc("GetVolumeInformationW")
	procGetFileInformationByEx  = volumeKernel32.NewProc("GetFileInformationByHandleEx")
)

type nativeFileIDInfo struct {
	VolumeSerial uint64
	FileID       [16]byte
}

// Compile-time ABI check for FILE_ID_INFO (8-byte serial + 16-byte file ID).
var (
	_ [24 - unsafe.Sizeof(nativeFileIDInfo{})]byte
	_ [unsafe.Sizeof(nativeFileIDInfo{}) - 24]byte
)

// Enumerate discovers Windows-managed local volume GUIDs without opening a
// raw disk or changing any state. It includes volumes without drive letters;
// unsupported/unavailable volumes are reported rather than silently ignored.
//
// Discovery is *not* authorization. FI must perform explicit enrollment
// validation and native re-attestation before any helper is allowed to read
// a journal, and installer approval remains a separate boundary.
func Enumerate(ctx context.Context) ([]Snapshot, error) {
	if ctx == nil {
		return nil, errors.New("discovery context is required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	buffer := make([]uint16, maxVolumeNameUnits)
	first, _, callErr := procFindFirstVolumeW.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
	)
	if first == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("FindFirstVolumeW: %w", callErr)
	}
	defer procFindVolumeClose.Call(first)

	var found []Snapshot
	seen := map[string]struct{}{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rawName := syscall.UTF16ToString(buffer)
		guid, err := canonicalGUID(rawName)
		if err != nil {
			return nil, fmt.Errorf("FindFirst/NextVolumeW returned an invalid volume GUID: %w", err)
		}
		if _, exists := seen[guid]; exists {
			return nil, fmt.Errorf("native volume enumerator returned duplicate GUID %q", guid)
		}
		if len(seen) >= maxDiscoveredVolumes {
			return nil, fmt.Errorf("native volume inventory exceeds the safe limit of %d volumes", maxDiscoveredVolumes)
		}
		seen[guid] = struct{}{}
		found = append(found, probeVolume(ctx, guid))

		for i := range buffer {
			buffer[i] = 0
		}
		next, _, nextErr := procFindNextVolumeW.Call(
			first,
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
		)
		if next != 0 {
			continue
		}
		if errors.Is(nextErr, errorNoMoreFiles) {
			break
		}
		return nil, fmt.Errorf("FindNextVolumeW: %w", nextErr)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].GUID < found[j].GUID })
	return found, nil
}

func probeVolume(ctx context.Context, guid string) Snapshot {
	item := Snapshot{GUID: guid}
	if err := ctx.Err(); err != nil {
		item.Status, item.Detail = Unavailable, err.Error()
		return item
	}
	mounts, err := queryVolumeMountPaths(guid)
	if err != nil {
		item.MountPathError = err.Error() // informational; not an identity input
	} else {
		item.MountPaths = mounts
	}

	path, err := syscall.UTF16PtrFromString(guid)
	if err != nil {
		item.Status, item.Detail = Unavailable, fmt.Sprintf("volume locator encoding: %v", err)
		return item
	}
	var fsName [64]uint16
	result, _, callErr := procGetVolumeInformationW.Call(
		uintptr(unsafe.Pointer(path)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&fsName[0])),
		uintptr(len(fsName)),
	)
	if result == 0 {
		item.Status, item.Detail = Unavailable, fmt.Sprintf("GetVolumeInformationW: %v", callErr)
		return item
	}
	item.FileSystem = syscall.UTF16ToString(fsName[:])
	if !strings.EqualFold(item.FileSystem, "NTFS") {
		item.Status, item.Detail = Unsupported, "filesystem is not NTFS"
		return item
	}
	item.FileSystem = "NTFS"

	// Opening the volume's *root directory* by its unique volume GUID does
	// not grant the caller raw-volume or file-content access. The only
	// requested right is FILE_READ_ATTRIBUTES and the handle is read-only.
	h, err := syscall.CreateFile(
		path,
		fileReadAttributes,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		item.Status, item.Detail = Unavailable, fmt.Sprintf("open volume root attributes: %v", err)
		return item
	}
	defer syscall.CloseHandle(h)

	if err := ctx.Err(); err != nil {
		item.Status, item.Detail = Unavailable, err.Error()
		return item
	}
	var info nativeFileIDInfo
	ok, _, callErr := procGetFileInformationByEx.Call(
		uintptr(h),
		fileIDInfoClass,
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if ok == 0 {
		item.Status, item.Detail = Unavailable, fmt.Sprintf("GetFileInformationByHandleEx(FileIdInfo): %v", callErr)
		return item
	}
	item.Serial64 = strconv.FormatUint(info.VolumeSerial, 10)
	if err := validSerial(item.Serial64); err != nil {
		item.Status, item.Detail = Unavailable, fmt.Sprintf("invalid native NTFS serial: %v", err)
		item.Serial64 = ""
		return item
	}
	item.Status = Eligible
	return item
}

// queryVolumeMountPaths returns informational DOS drive/mount aliases.
// An empty result is valid: a Windows volume may have no mounted paths.
func queryVolumeMountPaths(guid string) ([]string, error) {
	ptr, err := syscall.UTF16PtrFromString(guid)
	if err != nil {
		return nil, err
	}
	size := uint32(256)
	for {
		if size > maxMountPathUnits {
			return nil, errors.New("volume mount path list exceeds bounded capacity")
		}
		buffer := make([]uint16, size)
		var required uint32
		ok, _, callErr := procGetVolumePathNamesW.Call(
			uintptr(unsafe.Pointer(ptr)),
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(size),
			uintptr(unsafe.Pointer(&required)),
		)
		if ok != 0 {
			mounts, err := decodeMountPathList(buffer)
			if err != nil {
				return nil, err
			}
			sort.Strings(mounts)
			return mounts, nil
		}
		if !errors.Is(callErr, errorMoreData) && !errors.Is(callErr, errorBufferTooSmall) {
			return nil, fmt.Errorf("GetVolumePathNamesForVolumeNameW: %w", callErr)
		}
		// Account for concurrent mount changes and the API's required-size
		// contract without unbounded retries or allocation growth.
		if required <= size {
			required = size * 2
		}
		if required > maxMountPathUnits {
			return nil, errors.New("native mount list is unreasonably large")
		}
		size = required
	}
}

// Windows returns a MULTI_SZ (one or more NUL-terminated paths plus a final
// NUL). Never trust a partial result or use path strings as authorization IDs.
func decodeMountPathList(buffer []uint16) ([]string, error) {
	if len(buffer) == 0 {
		return nil, errors.New("empty mount list buffer")
	}
	var mounts []string
	for offset := 0; offset < len(buffer); {
		if buffer[offset] == 0 {
			return mounts, nil
		}
		end := offset
		for end < len(buffer) && buffer[end] != 0 {
			end++
		}
		if end == len(buffer) {
			return nil, errors.New("unterminated native mount path")
		}
		mounts = append(mounts, syscall.UTF16ToString(buffer[offset:end]))
		offset = end + 1
	}
	return nil, errors.New("native mount list missing final terminator")
}
