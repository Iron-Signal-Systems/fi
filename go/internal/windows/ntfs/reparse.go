// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package ntfs

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

// Reference:
// Microsoft Open Specifications [MS-FSCC], section 2.1.2.1, "Reparse Tags".
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/c8e77b37-3909-4fe6-a4ea-2b9d423b1ee4
const (
	reparseTagMountPoint uint32 = 0xA0000003
	reparseTagSymlink    uint32 = 0xA000000C
)

// nativeReparseData is the Windows-side parsed representation of one exact
// FSCTL_GET_REPARSE_POINT buffer. RawBuffer is always retained.
type nativeReparseData struct {
	DataFormat        records.ReparseDataFormat
	PrintName         []uint16
	RawBuffer         []byte
	SubstituteName    []uint16
	SymbolicLinkFlags uint32
	Tag               uint32
}

// parseReparseData parses only documented layouts FI understands exactly.
//
// Reference:
// Microsoft Learn, "REPARSE_DATA_BUFFER structure (ntifs.h)".
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_data_buffer
//
// Mount-point and symbolic-link offsets are byte offsets from PathBuffer. Other
// tags remain Raw; FI preserves the exact returned bytes without guessing at an
// owner-defined format.
func parseReparseData(raw []byte) (nativeReparseData, error) {
	if len(raw) < 8 {
		return nativeReparseData{}, ErrMalformedReparseData
	}

	tag := binary.LittleEndian.Uint32(raw[0:4])
	dataLength := int(binary.LittleEndian.Uint16(raw[4:6]))
	dataEnd := 8 + dataLength
	if dataEnd > len(raw) {
		return nativeReparseData{}, ErrMalformedReparseData
	}

	data := nativeReparseData{
		DataFormat: records.ReparseDataFormatRaw,
		RawBuffer:  append([]byte(nil), raw...),
		Tag:        tag,
	}

	switch tag {
	case reparseTagMountPoint:
		if dataLength < 8 || dataEnd < 16 {
			return nativeReparseData{}, ErrMalformedReparseData
		}

		substituteOffset := int(binary.LittleEndian.Uint16(raw[8:10]))
		substituteLength := int(binary.LittleEndian.Uint16(raw[10:12]))
		printOffset := int(binary.LittleEndian.Uint16(raw[12:14]))
		printLength := int(binary.LittleEndian.Uint16(raw[14:16]))

		substituteName, err := utf16FromReparsePath(raw, 16, substituteOffset, substituteLength, dataEnd)
		if err != nil {
			return nativeReparseData{}, err
		}
		printName, err := utf16FromReparsePath(raw, 16, printOffset, printLength, dataEnd)
		if err != nil {
			return nativeReparseData{}, err
		}

		data.DataFormat = records.ReparseDataFormatMountPoint
		data.PrintName = printName
		data.SubstituteName = substituteName
		return data, nil

	case reparseTagSymlink:
		if dataLength < 12 || dataEnd < 20 {
			return nativeReparseData{}, ErrMalformedReparseData
		}

		substituteOffset := int(binary.LittleEndian.Uint16(raw[8:10]))
		substituteLength := int(binary.LittleEndian.Uint16(raw[10:12]))
		printOffset := int(binary.LittleEndian.Uint16(raw[12:14]))
		printLength := int(binary.LittleEndian.Uint16(raw[14:16]))

		substituteName, err := utf16FromReparsePath(raw, 20, substituteOffset, substituteLength, dataEnd)
		if err != nil {
			return nativeReparseData{}, err
		}
		printName, err := utf16FromReparsePath(raw, 20, printOffset, printLength, dataEnd)
		if err != nil {
			return nativeReparseData{}, err
		}

		data.DataFormat = records.ReparseDataFormatSymbolicLink
		data.PrintName = printName
		data.SubstituteName = substituteName
		data.SymbolicLinkFlags = binary.LittleEndian.Uint32(raw[16:20])
		return data, nil

	default:
		return data, nil
	}
}

func reparseObservationError(tag uint32, reasonCode string) records.ReparseObservation {
	tagValue := reparseTagString(tag)
	return records.ReparseObservation{
		DataFormat: records.ReparseDataFormatNotKnown,
		DataState:  records.ReparseDataStateError,
		ReasonCode: reasonCode,
		State:      records.ReparseStatePresent,
		Tag:        tagValue,
		TagName:    records.ReparseTagName(tagValue),
	}
}

func reparseObservationNotPresent() records.ReparseObservation {
	return records.ReparseObservation{
		DataFormat: records.ReparseDataFormatNotApplicable,
		DataState:  records.ReparseDataStateNotApplicable,
		State:      records.ReparseStateNotPresent,
	}
}

func reparseObservationParsed(data nativeReparseData) records.ReparseObservation {
	tagValue := reparseTagString(data.Tag)
	observation := records.ReparseObservation{
		DataFormat:         data.DataFormat,
		DataState:          records.ReparseDataStatePresent,
		RawBufferBase64URL: base64.RawURLEncoding.EncodeToString(data.RawBuffer),
		State:              records.ReparseStatePresent,
		Tag:                tagValue,
		TagName:            records.ReparseTagName(tagValue),
	}

	switch data.DataFormat {
	case records.ReparseDataFormatMountPoint:
		observation.PrintNameUTF16LEBase64URL = utf16LEBase64URL(data.PrintName)
		observation.SubstituteNameUTF16LEBase64URL = utf16LEBase64URL(data.SubstituteName)
	case records.ReparseDataFormatSymbolicLink:
		observation.PrintNameUTF16LEBase64URL = utf16LEBase64URL(data.PrintName)
		observation.SubstituteNameUTF16LEBase64URL = utf16LEBase64URL(data.SubstituteName)
		observation.SymbolicLinkFlags = fmt.Sprintf("0x%08X", data.SymbolicLinkFlags)
	}

	return observation
}

func reparseObservationRaw(tag uint32, raw []byte, reasonCode string) records.ReparseObservation {
	tagValue := reparseTagString(tag)
	return records.ReparseObservation{
		DataFormat:         records.ReparseDataFormatRaw,
		DataState:          records.ReparseDataStatePresent,
		RawBufferBase64URL: base64.RawURLEncoding.EncodeToString(raw),
		ReasonCode:         reasonCode,
		State:              records.ReparseStatePresent,
		Tag:                tagValue,
		TagName:            records.ReparseTagName(tagValue),
	}
}

func reparseTagString(tag uint32) string {
	return fmt.Sprintf("0x%08X", tag)
}

func utf16FromReparsePath(raw []byte, pathStart int, offset int, length int, dataEnd int) ([]uint16, error) {
	if offset < 0 || length < 0 || offset%2 != 0 || length%2 != 0 {
		return nil, ErrMalformedReparseData
	}

	start := pathStart + offset
	end := start + length
	if start < pathStart || end < start || end > dataEnd || end > len(raw) {
		return nil, ErrMalformedReparseData
	}

	units := make([]uint16, length/2)
	for index := range units {
		position := start + index*2
		units[index] = binary.LittleEndian.Uint16(raw[position : position+2])
	}
	return units, nil
}
