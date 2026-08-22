// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package smb

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const (
	netShareInfoLevel502                 = 502
	netShareMaxPreferredLength           = 0xffffffff
	netAPISuccess                        = 0
	netAPIErrorAccessDenied              = 5
	netAPIErrorMoreData                  = 234
	maxShareUTF16Units                   = 32768
	maximumShareSecurityDescriptorBuffer = 128 * 1024
)

type shareInfo502 struct {
	NetName            *uint16
	Type               uint32
	Remark             *uint16
	Permissions        uint32
	MaxUses            uint32
	CurrentUses        uint32
	Path               *uint16
	Password           *uint16
	Reserved           uint32
	SecurityDescriptor uintptr
}

type netAPIStatusError struct {
	Operation string
	Status    uint32
}

func (e *netAPIStatusError) Error() string {
	return fmt.Sprintf("%s: NET_API_STATUS %d", e.Operation, e.Status)
}

var (
	smbNetapi32                     = syscall.NewLazyDLL("netapi32.dll")
	smbAdvapi32                     = syscall.NewLazyDLL("advapi32.dll")
	procNetShareEnum                = smbNetapi32.NewProc("NetShareEnum")
	procNetApiBufferFree            = smbNetapi32.NewProc("NetApiBufferFree")
	procIsValidSecurityDescriptor   = smbAdvapi32.NewProc("IsValidSecurityDescriptor")
	procGetSecurityDescriptorLength = smbAdvapi32.NewProc("GetSecurityDescriptorLength")
)

// CollectLocalShares records the current local Windows SMB share inventory.
// It deliberately remains a server-level snapshot rather than embedding share
// state into every NTFS file observation.
func CollectLocalShares(ctx context.Context) (records.SMBShareSnapshot, error) {
	if err := validateContext(ctx); err != nil {
		return records.SMBShareSnapshot{}, err
	}

	shares := []records.SMBShareObservation{}
	var resumeHandle uint32
	for {
		if err := validateContext(ctx); err != nil {
			return records.SMBShareSnapshot{}, err
		}

		var buffer uintptr
		var entriesRead uint32
		var totalEntries uint32
		status, _, _ := procNetShareEnum.Call(
			0,
			netShareInfoLevel502,
			uintptr(unsafe.Pointer(&buffer)),
			netShareMaxPreferredLength,
			uintptr(unsafe.Pointer(&entriesRead)),
			uintptr(unsafe.Pointer(&totalEntries)),
			uintptr(unsafe.Pointer(&resumeHandle)),
		)
		netStatus := uint32(status)

		var page []records.SMBShareObservation
		var pageErr error
		if buffer != 0 {
			page, pageErr = convertSharePage(buffer, entriesRead)
			freeStatus, _, _ := procNetApiBufferFree.Call(buffer)
			if pageErr == nil && uint32(freeStatus) != netAPISuccess {
				pageErr = &netAPIStatusError{Operation: "NetApiBufferFree", Status: uint32(freeStatus)}
			}
		}
		if pageErr != nil {
			return records.SMBShareSnapshot{}, pageErr
		}
		shares = append(shares, page...)

		switch netStatus {
		case netAPISuccess:
			goto complete
		case netAPIErrorMoreData:
			if entriesRead == 0 {
				return records.SMBShareSnapshot{}, fmt.Errorf("NetShareEnum returned ERROR_MORE_DATA without progress")
			}
		default:
			return records.SMBShareSnapshot{}, &netAPIStatusError{Operation: "NetShareEnum", Status: netStatus}
		}
	}

complete:
	sort.Slice(shares, func(i, j int) bool {
		return shares[i].NameUTF16LEBase64URL < shares[j].NameUTF16LEBase64URL
	})

	snapshot := records.SMBShareSnapshot{
		ObservedAt:       time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
		CollectionMethod: records.SMBShareCollectionWindowsNetShareEnum502,
		Shares:           shares,
	}
	if err := records.ValidateSMBShareSnapshot(snapshot); err != nil {
		return records.SMBShareSnapshot{}, fmt.Errorf("validate SMB share snapshot: %w", err)
	}
	return snapshot, nil
}

func convertSharePage(buffer uintptr, entriesRead uint32) ([]records.SMBShareObservation, error) {
	if entriesRead == 0 {
		return []records.SMBShareObservation{}, nil
	}
	if buffer == 0 {
		return nil, fmt.Errorf("NetShareEnum returned entries without a buffer")
	}
	entries := unsafe.Slice((*shareInfo502)(unsafe.Pointer(buffer)), int(entriesRead))
	shares := make([]records.SMBShareObservation, 0, entriesRead)
	for index := range entries {
		share, err := convertShare(entries[index])
		if err != nil {
			return nil, fmt.Errorf("share[%d]: %w", index, err)
		}
		shares = append(shares, share)
	}
	return shares, nil
}

func convertShare(native shareInfo502) (records.SMBShareObservation, error) {
	nameUnits, err := utf16UnitsFromPointer(native.NetName)
	if err != nil {
		return records.SMBShareObservation{}, fmt.Errorf("name: %w", err)
	}
	if len(nameUnits) == 0 {
		return records.SMBShareObservation{}, fmt.Errorf("share name is empty")
	}
	remarkUnits, err := optionalUTF16UnitsFromPointer(native.Remark)
	if err != nil {
		return records.SMBShareObservation{}, fmt.Errorf("remark: %w", err)
	}
	pathUnits, err := optionalUTF16UnitsFromPointer(native.Path)
	if err != nil {
		return records.SMBShareObservation{}, fmt.Errorf("path: %w", err)
	}

	typeName, special, temporary := records.ClassifySMBShareType(native.Type)
	return records.SMBShareObservation{
		NameDisplay:               utf16Display(nameUnits),
		NameUTF16LEBase64URL:      utf16LEBase64URL(nameUnits),
		TypeRaw:                   strconv.FormatUint(uint64(native.Type), 10),
		TypeName:                  typeName,
		Special:                   special,
		Temporary:                 temporary,
		RemarkDisplay:             utf16Display(remarkUnits),
		RemarkUTF16LEBase64URL:    utf16LEBase64URL(remarkUnits),
		LocalPathDisplay:          utf16Display(pathUnits),
		LocalPathUTF16LEBase64URL: utf16LEBase64URL(pathUnits),
		PermissionsRaw:            strconv.FormatUint(uint64(native.Permissions), 10),
		MaxUsesRaw:                strconv.FormatUint(uint64(native.MaxUses), 10),
		CurrentUses:               strconv.FormatUint(uint64(native.CurrentUses), 10),
		Security:                  shareSecurityObservation(native.SecurityDescriptor),
	}, nil
}

func shareSecurityObservation(pointer uintptr) records.SecurityObservation {
	if pointer == 0 {
		return records.SecurityObservationError("ShareSecurityDescriptorNotReturned")
	}
	valid, _, _ := procIsValidSecurityDescriptor.Call(pointer)
	if valid == 0 {
		return records.SecurityObservationError("ShareSecurityDescriptorInvalid")
	}
	length, _, _ := procGetSecurityDescriptorLength.Call(pointer)
	if length == 0 {
		return records.SecurityObservationError("ShareSecurityDescriptorLengthInvalid")
	}
	if length > maximumShareSecurityDescriptorBuffer {
		return records.SecurityObservationError("ShareSecurityDescriptorTooLarge")
	}

	raw := append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(pointer)), int(length))...)
	parsed, err := records.ParseSecurityDescriptor(raw)
	if err != nil {
		return records.RawSecurityObservation(raw, "ShareSecurityDescriptorParseFailed")
	}
	return parsed
}

func optionalUTF16UnitsFromPointer(pointer *uint16) ([]uint16, error) {
	if pointer == nil {
		return []uint16{}, nil
	}
	return utf16UnitsFromPointer(pointer)
}

func utf16UnitsFromPointer(pointer *uint16) ([]uint16, error) {
	if pointer == nil {
		return nil, fmt.Errorf("NULL UTF-16 pointer")
	}
	view := unsafe.Slice(pointer, maxShareUTF16Units)
	for index, unit := range view {
		if unit == 0 {
			return append([]uint16(nil), view[:index]...), nil
		}
	}
	return nil, fmt.Errorf("UTF-16 string exceeds bounded length")
}

func utf16Display(units []uint16) string {
	return string(utf16.Decode(units))
}

func utf16LEBase64URL(units []uint16) string {
	if len(units) == 0 {
		return ""
	}
	raw := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(raw[index*2:], unit)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
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
