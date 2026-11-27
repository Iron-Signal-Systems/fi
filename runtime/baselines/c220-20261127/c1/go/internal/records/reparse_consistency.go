// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

const (
	reparseTagMountPointCanonical = "0xA0000003"
	reparseTagSymlinkCanonical    = "0xA000000C"
)

type parsedKnownReparse struct {
	DataFormat                     ReparseDataFormat
	PrintNameUTF16LEBase64URL      string
	SubstituteNameUTF16LEBase64URL string
	SymbolicLinkFlags              string
}

// parseKnownReparseBuffer parses only the documented reparse layouts FI claims
// to interpret. Unknown tags return known=false so they can remain raw without
// inventing owner-defined semantics.
func parseKnownReparseBuffer(raw []byte) (parsedKnownReparse, bool, error) {
	if len(raw) < 8 {
		return parsedKnownReparse{}, false, fmt.Errorf("reparse buffer shorter than header")
	}

	tag := fmt.Sprintf("0x%08X", binary.LittleEndian.Uint32(raw[0:4]))
	dataLength := int(binary.LittleEndian.Uint16(raw[4:6]))
	dataEnd := 8 + dataLength
	if dataEnd < 8 || dataEnd > len(raw) {
		return parsedKnownReparse{}, tag == reparseTagMountPointCanonical || tag == reparseTagSymlinkCanonical,
			fmt.Errorf("reparse data length exceeds buffer")
	}

	switch tag {
	case reparseTagMountPointCanonical:
		if dataLength < 8 || dataEnd < 16 {
			return parsedKnownReparse{}, true, fmt.Errorf("mount-point payload too short")
		}
		substitute, err := reparseUTF16Field(raw, 16,
			int(binary.LittleEndian.Uint16(raw[8:10])),
			int(binary.LittleEndian.Uint16(raw[10:12])), dataEnd)
		if err != nil {
			return parsedKnownReparse{}, true, err
		}
		printName, err := reparseUTF16Field(raw, 16,
			int(binary.LittleEndian.Uint16(raw[12:14])),
			int(binary.LittleEndian.Uint16(raw[14:16])), dataEnd)
		if err != nil {
			return parsedKnownReparse{}, true, err
		}
		return parsedKnownReparse{
			DataFormat:                     ReparseDataFormatMountPoint,
			PrintNameUTF16LEBase64URL:      printName,
			SubstituteNameUTF16LEBase64URL: substitute,
		}, true, nil

	case reparseTagSymlinkCanonical:
		if dataLength < 12 || dataEnd < 20 {
			return parsedKnownReparse{}, true, fmt.Errorf("symbolic-link payload too short")
		}
		substitute, err := reparseUTF16Field(raw, 20,
			int(binary.LittleEndian.Uint16(raw[8:10])),
			int(binary.LittleEndian.Uint16(raw[10:12])), dataEnd)
		if err != nil {
			return parsedKnownReparse{}, true, err
		}
		printName, err := reparseUTF16Field(raw, 20,
			int(binary.LittleEndian.Uint16(raw[12:14])),
			int(binary.LittleEndian.Uint16(raw[14:16])), dataEnd)
		if err != nil {
			return parsedKnownReparse{}, true, err
		}
		return parsedKnownReparse{
			DataFormat:                     ReparseDataFormatSymbolicLink,
			PrintNameUTF16LEBase64URL:      printName,
			SubstituteNameUTF16LEBase64URL: substitute,
			SymbolicLinkFlags:              fmt.Sprintf("0x%08X", binary.LittleEndian.Uint32(raw[16:20])),
		}, true, nil

	default:
		return parsedKnownReparse{}, false, nil
	}
}

func reparseUTF16Field(raw []byte, pathStart int, offset int, length int, dataEnd int) (string, error) {
	if offset < 0 || length < 0 || offset%2 != 0 || length%2 != 0 {
		return "", fmt.Errorf("invalid UTF-16 reparse offset or length")
	}
	start := pathStart + offset
	end := start + length
	if start < pathStart || end < start || end > dataEnd || end > len(raw) {
		return "", fmt.Errorf("reparse UTF-16 field exceeds payload")
	}
	return base64.RawURLEncoding.EncodeToString(raw[start:end]), nil
}

func validateReparsePayloadConsistency(reparse ReparseObservation, raw []byte) error {
	parsed, known, parseErr := parseKnownReparseBuffer(raw)

	switch reparse.DataFormat {
	case ReparseDataFormatMountPoint:
		if !known || parseErr != nil || parsed.DataFormat != ReparseDataFormatMountPoint {
			return invalid("InvalidReparseBuffer", "reparse.raw_buffer_base64url")
		}
		if reparse.PrintNameUTF16LEBase64URL != "" {
			if err := validateUTF16LEBase64URL(reparse.PrintNameUTF16LEBase64URL, "reparse.print_name_utf16le_base64url"); err != nil {
				return err
			}
		}
		if reparse.SubstituteNameUTF16LEBase64URL != "" {
			if err := validateUTF16LEBase64URL(reparse.SubstituteNameUTF16LEBase64URL, "reparse.substitute_name_utf16le_base64url"); err != nil {
				return err
			}
		}
		if reparse.PrintNameUTF16LEBase64URL != parsed.PrintNameUTF16LEBase64URL {
			return invalid("Conflict", "reparse.print_name_utf16le_base64url")
		}
		if reparse.SubstituteNameUTF16LEBase64URL != parsed.SubstituteNameUTF16LEBase64URL {
			return invalid("Conflict", "reparse.substitute_name_utf16le_base64url")
		}
		return nil

	case ReparseDataFormatSymbolicLink:
		if !known || parseErr != nil || parsed.DataFormat != ReparseDataFormatSymbolicLink {
			return invalid("InvalidReparseBuffer", "reparse.raw_buffer_base64url")
		}
		if err := validateHex32(reparse.SymbolicLinkFlags, "reparse.symbolic_link_flags"); err != nil {
			return err
		}
		if reparse.PrintNameUTF16LEBase64URL != "" {
			if err := validateUTF16LEBase64URL(reparse.PrintNameUTF16LEBase64URL, "reparse.print_name_utf16le_base64url"); err != nil {
				return err
			}
		}
		if reparse.SubstituteNameUTF16LEBase64URL != "" {
			if err := validateUTF16LEBase64URL(reparse.SubstituteNameUTF16LEBase64URL, "reparse.substitute_name_utf16le_base64url"); err != nil {
				return err
			}
		}
		if reparse.PrintNameUTF16LEBase64URL != parsed.PrintNameUTF16LEBase64URL {
			return invalid("Conflict", "reparse.print_name_utf16le_base64url")
		}
		if reparse.SubstituteNameUTF16LEBase64URL != parsed.SubstituteNameUTF16LEBase64URL {
			return invalid("Conflict", "reparse.substitute_name_utf16le_base64url")
		}
		if reparse.SymbolicLinkFlags != parsed.SymbolicLinkFlags {
			return invalid("Conflict", "reparse.symbolic_link_flags")
		}
		return nil

	case ReparseDataFormatRaw:
		if known && parseErr == nil {
			return invalid("Conflict", "reparse.data_format")
		}
		if known && parseErr != nil && reparse.ReasonCode == "" {
			return invalid("Required", "reparse.reason_code")
		}
		return nil

	default:
		return nil
	}
}
