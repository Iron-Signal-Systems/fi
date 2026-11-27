// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"encoding/binary"
	"strconv"
	"unicode/utf16"
)

// SMBShareCollectionMethod identifies the Windows source used for the local
// SMB share snapshot.
type SMBShareCollectionMethod string

const (
	SMBShareCollectionWindowsNetShareEnum502 SMBShareCollectionMethod = "WindowsNetShareEnum502"
)

// SMBShareTypeName is FI's deterministic label for the base STYPE value.
type SMBShareTypeName string

const (
	SMBShareTypeDevice     SMBShareTypeName = "Device"
	SMBShareTypeDiskTree   SMBShareTypeName = "DiskTree"
	SMBShareTypeIPC        SMBShareTypeName = "IPC"
	SMBShareTypeNotKnown   SMBShareTypeName = "NotKnown"
	SMBShareTypePrintQueue SMBShareTypeName = "PrintQueue"
)

const (
	smbShareTypeMask      uint32 = 0x000000ff
	smbShareTypeSpecial   uint32 = 0x80000000
	smbShareTypeTemporary uint32 = 0x40000000
)

// SMBShareSnapshot records one local Windows SMB server share inventory.
//
// Share state is intentionally separate from NTFS object observations. The
// backend can correlate a share's local path with file observations at the
// appropriate time without duplicating server-wide share state into every file
// record.
type SMBShareSnapshot struct {
	ObservedAt       string                   `json:"observed_at"`
	CollectionMethod SMBShareCollectionMethod `json:"collection_method"`
	Shares           []SMBShareObservation    `json:"shares"`
}

// SMBShareObservation records the source facts returned for one local SMB
// share. UTF-16LE base64url fields are authoritative; display fields are
// deterministic convenience projections.
//
// PermissionsRaw preserves the legacy SHARE_INFO_502 permissions member. It is
// not treated as the authoritative Windows share ACL. Security contains the
// share's security descriptor and DACL.
type SMBShareObservation struct {
	NameDisplay               string              `json:"name_display"`
	NameUTF16LEBase64URL      string              `json:"name_utf16le_base64url"`
	TypeRaw                   string              `json:"type_raw"`
	TypeName                  SMBShareTypeName    `json:"type_name"`
	Special                   bool                `json:"special"`
	Temporary                 bool                `json:"temporary"`
	RemarkDisplay             string              `json:"remark_display,omitempty"`
	RemarkUTF16LEBase64URL    string              `json:"remark_utf16le_base64url,omitempty"`
	LocalPathDisplay          string              `json:"local_path_display,omitempty"`
	LocalPathUTF16LEBase64URL string              `json:"local_path_utf16le_base64url,omitempty"`
	PermissionsRaw            string              `json:"permissions_raw"`
	MaxUsesRaw                string              `json:"max_uses_raw"`
	CurrentUses               string              `json:"current_uses"`
	Security                  SecurityObservation `json:"security"`
}

// ClassifySMBShareType converts the exact 32-bit SHARE_INFO_502 type into FI's
// base label and the independent special/temporary flags.
func ClassifySMBShareType(raw uint32) (SMBShareTypeName, bool, bool) {
	var name SMBShareTypeName
	switch raw & smbShareTypeMask {
	case 0:
		name = SMBShareTypeDiskTree
	case 1:
		name = SMBShareTypePrintQueue
	case 2:
		name = SMBShareTypeDevice
	case 3:
		name = SMBShareTypeIPC
	default:
		name = SMBShareTypeNotKnown
	}
	return name, raw&smbShareTypeSpecial != 0, raw&smbShareTypeTemporary != 0
}

// ValidateSMBShareSnapshot validates the deterministic shared representation.
func ValidateSMBShareSnapshot(snapshot SMBShareSnapshot) error {
	if err := ValidateObservedAt(snapshot.ObservedAt); err != nil {
		return err
	}
	if snapshot.CollectionMethod != SMBShareCollectionWindowsNetShareEnum502 {
		return invalid("UnsupportedValue", "collection_method")
	}

	previous := ""
	for index, share := range snapshot.Shares {
		if err := ValidateSMBShareObservation(share); err != nil {
			return err
		}
		if previous != "" && share.NameUTF16LEBase64URL <= previous {
			return invalid("UnsortedCollection", "shares")
		}
		previous = share.NameUTF16LEBase64URL

		// Keep index evaluation in the validation boundary so duplicate or
		// unsorted records always fail deterministically at the snapshot level.
		_ = index
	}
	return nil
}

// ValidateSMBShareObservation validates one share and its share DACL record.
func ValidateSMBShareObservation(share SMBShareObservation) error {
	if err := validateSMBShareUTF16Pair(
		share.NameDisplay,
		share.NameUTF16LEBase64URL,
		"share.name",
		true,
	); err != nil {
		return err
	}
	if err := validateSMBShareUTF16Pair(
		share.RemarkDisplay,
		share.RemarkUTF16LEBase64URL,
		"share.remark",
		false,
	); err != nil {
		return err
	}
	if err := validateSMBShareUTF16Pair(
		share.LocalPathDisplay,
		share.LocalPathUTF16LEBase64URL,
		"share.local_path",
		false,
	); err != nil {
		return err
	}

	rawType, err := smbShareUint32(share.TypeRaw, "share.type_raw")
	if err != nil {
		return err
	}
	typeName, special, temporary := ClassifySMBShareType(rawType)
	if share.TypeName != typeName || share.Special != special || share.Temporary != temporary {
		return invalid("Conflict", "share.type")
	}

	if _, err := smbShareUint32(share.PermissionsRaw, "share.permissions_raw"); err != nil {
		return err
	}
	if _, err := smbShareUint32(share.MaxUsesRaw, "share.max_uses_raw"); err != nil {
		return err
	}
	if _, err := smbShareUint32(share.CurrentUses, "share.current_uses"); err != nil {
		return err
	}

	return ValidateSecurityObservation(share.Security)
}

func validateSMBShareUTF16Pair(display, encoded, field string, required bool) error {
	if encoded == "" {
		if required {
			return invalid("Required", field+"_utf16le_base64url")
		}
		if display != "" {
			return invalid("Conflict", field)
		}
		return nil
	}
	if err := validateUTF16LEBase64URL(encoded, field+"_utf16le_base64url"); err != nil {
		return err
	}
	decoded, err := decodeBase64URL(encoded, field+"_utf16le_base64url")
	if err != nil {
		return err
	}
	units := make([]uint16, len(decoded)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(decoded[index*2:])
	}
	if string(utf16.Decode(units)) != display {
		return invalid("Conflict", field+"_display")
	}
	if required && display == "" {
		return invalid("Required", field+"_display")
	}
	return nil
}

func smbShareUint32(value, field string) (uint32, error) {
	if value == "" {
		return 0, invalid("Required", field)
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		return 0, invalid("InvalidDecimal", field)
	}
	if strconv.FormatUint(parsed, 10) != value {
		return 0, invalid("NonCanonical", field)
	}
	return uint32(parsed), nil
}
