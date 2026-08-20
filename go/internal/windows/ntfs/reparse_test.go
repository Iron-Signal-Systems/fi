// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package ntfs

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestParseReparseDataMountPoint(t *testing.T) {
	raw := testMountPointReparseData(`\??\C:\target`, `C:\target`)
	got, err := parseReparseData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.DataFormat != records.ReparseDataFormatMountPoint || got.Tag != reparseTagMountPoint {
		t.Fatalf("parsed = %+v", got)
	}
	if !bytes.Equal(testUTF16Bytes(got.SubstituteName), testUTF16Bytes(testUTF16(`\??\C:\target`))) {
		t.Fatalf("substitute = %v", got.SubstituteName)
	}
	if !bytes.Equal(testUTF16Bytes(got.PrintName), testUTF16Bytes(testUTF16(`C:\target`))) {
		t.Fatalf("print = %v", got.PrintName)
	}
}

func TestParseReparseDataRejectsInvalidOffset(t *testing.T) {
	raw := testMountPointReparseData(`\??\C:\target`, `C:\target`)
	binary.LittleEndian.PutUint16(raw[8:10], 0xFFFF)

	if _, err := parseReparseData(raw); err == nil {
		t.Fatal("expected malformed reparse data error")
	}
}

func TestParseReparseDataSymbolicLink(t *testing.T) {
	raw := testSymbolicLinkReparseData(`\??\C:\target.txt`, `C:\target.txt`, 0)
	got, err := parseReparseData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.DataFormat != records.ReparseDataFormatSymbolicLink || got.Tag != reparseTagSymlink {
		t.Fatalf("parsed = %+v", got)
	}
	if got.SymbolicLinkFlags != 0 {
		t.Fatalf("flags = 0x%08X", got.SymbolicLinkFlags)
	}
}

func TestParseReparseDataUnknownPreservesRaw(t *testing.T) {
	raw := make([]byte, 28)
	binary.LittleEndian.PutUint32(raw[0:4], 0xDEADBEEF)
	binary.LittleEndian.PutUint16(raw[4:6], 4)
	copy(raw[8:24], []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	copy(raw[24:], []byte{1, 2, 3, 4})

	got, err := parseReparseData(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.DataFormat != records.ReparseDataFormatRaw || got.Tag != 0xDEADBEEF {
		t.Fatalf("parsed = %+v", got)
	}
	if !bytes.Equal(got.RawBuffer, raw) {
		t.Fatal("raw reparse buffer was not preserved")
	}

	observation := reparseObservationParsed(got)
	if observation.TagName != records.ReparseTagNameNotKnown ||
		observation.RawBufferBase64URL == "" {
		t.Fatalf("observation = %+v", observation)
	}
}

func testMountPointReparseData(substitute string, print string) []byte {
	substituteBytes := testUTF16Bytes(testUTF16(substitute))
	printBytes := testUTF16Bytes(testUTF16(print))
	pathBytes := append(append([]byte(nil), substituteBytes...), printBytes...)

	dataLength := 8 + len(pathBytes)
	raw := make([]byte, 8+dataLength)
	binary.LittleEndian.PutUint32(raw[0:4], reparseTagMountPoint)
	binary.LittleEndian.PutUint16(raw[4:6], uint16(dataLength))
	binary.LittleEndian.PutUint16(raw[8:10], 0)
	binary.LittleEndian.PutUint16(raw[10:12], uint16(len(substituteBytes)))
	binary.LittleEndian.PutUint16(raw[12:14], uint16(len(substituteBytes)))
	binary.LittleEndian.PutUint16(raw[14:16], uint16(len(printBytes)))
	copy(raw[16:], pathBytes)
	return raw
}

func testSymbolicLinkReparseData(substitute string, print string, flags uint32) []byte {
	substituteBytes := testUTF16Bytes(testUTF16(substitute))
	printBytes := testUTF16Bytes(testUTF16(print))
	pathBytes := append(append([]byte(nil), substituteBytes...), printBytes...)

	dataLength := 12 + len(pathBytes)
	raw := make([]byte, 8+dataLength)
	binary.LittleEndian.PutUint32(raw[0:4], reparseTagSymlink)
	binary.LittleEndian.PutUint16(raw[4:6], uint16(dataLength))
	binary.LittleEndian.PutUint16(raw[8:10], 0)
	binary.LittleEndian.PutUint16(raw[10:12], uint16(len(substituteBytes)))
	binary.LittleEndian.PutUint16(raw[12:14], uint16(len(substituteBytes)))
	binary.LittleEndian.PutUint16(raw[14:16], uint16(len(printBytes)))
	binary.LittleEndian.PutUint32(raw[16:20], flags)
	copy(raw[20:], pathBytes)
	return raw
}

func testUTF16(value string) []uint16 {
	units := make([]uint16, len(value))
	for index := range value {
		units[index] = uint16(value[index])
	}
	return units
}

func testUTF16Bytes(units []uint16) []byte {
	encoded := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(encoded[index*2:], unit)
	}
	return encoded
}
