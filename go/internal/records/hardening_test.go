// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
)

func TestValidateReparseObservationRejectsMountPointParsedFieldMismatch(t *testing.T) {
	raw := hardeningMountPointBuffer(`\??\C:\Actual`, `C:\Actual`)
	observation := ReparseObservation{
		DataFormat:                     ReparseDataFormatMountPoint,
		DataState:                      ReparseDataStatePresent,
		PrintNameUTF16LEBase64URL:      hardeningUTF16Base64(`C:\SomethingElse`),
		RawBufferBase64URL:             base64.RawURLEncoding.EncodeToString(raw),
		State:                          ReparseStatePresent,
		SubstituteNameUTF16LEBase64URL: hardeningUTF16Base64(`\??\C:\Actual`),
		Tag:                            "0xA0000003",
		TagName:                        "IO_REPARSE_TAG_MOUNT_POINT",
	}
	if err := ValidateReparseObservation(observation); err == nil || !strings.Contains(err.Error(), "print_name") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateReparseObservationRejectsSymlinkFlagsMismatch(t *testing.T) {
	raw := hardeningSymlinkBuffer(`\??\C:\Actual`, `C:\Actual`, 0)
	observation := ReparseObservation{
		DataFormat:                     ReparseDataFormatSymbolicLink,
		DataState:                      ReparseDataStatePresent,
		PrintNameUTF16LEBase64URL:      hardeningUTF16Base64(`C:\Actual`),
		RawBufferBase64URL:             base64.RawURLEncoding.EncodeToString(raw),
		State:                          ReparseStatePresent,
		SubstituteNameUTF16LEBase64URL: hardeningUTF16Base64(`\??\C:\Actual`),
		SymbolicLinkFlags:              "0x00000001",
		Tag:                            "0xA000000C",
		TagName:                        "IO_REPARSE_TAG_SYMLINK",
	}
	if err := ValidateReparseObservation(observation); err == nil || !strings.Contains(err.Error(), "symbolic_link_flags") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateStreamIdentityRejectsInterpretationMismatch(t *testing.T) {
	identity := StreamIdentityFromRawUTF16(hardeningUTF16(`:secret:$DATA`))
	identity.NameUTF16LEBase64URL = hardeningUTF16Base64("innocent")
	if err := ValidateStreamIdentity(identity); err == nil || !strings.Contains(err.Error(), "Conflict") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateNTFSObjectIdentityBounds(t *testing.T) {
	valid := NTFSObjectIdentity{
		MethodVersion:       "windows-file-id-info-ntfs/0.1",
		FileReferenceNumber: "281474976710655",
		SequenceNumber:      "65535",
	}
	if err := ValidateNTFSObjectIdentity(valid); err != nil {
		t.Fatal(err)
	}
	valid.FileReferenceNumber = "281474976710656"
	if err := ValidateNTFSObjectIdentity(valid); err == nil || !strings.Contains(err.Error(), "OutOfRange") {
		t.Fatalf("file reference error = %v", err)
	}
	valid.FileReferenceNumber = "1"
	valid.SequenceNumber = "65536"
	if err := ValidateNTFSObjectIdentity(valid); err == nil || !strings.Contains(err.Error(), "OutOfRange") {
		t.Fatalf("sequence error = %v", err)
	}
}

func TestValidateVolumeIdentityGUIDShape(t *testing.T) {
	identity := VolumeIdentity{
		MethodVersion: "windows-file-id-info-ntfs/0.1",
		VolumeGUID:    `\\?\Volume{11111111-2222-3333-4444-555555555555}\`,
		VolumeSerial:  "1",
	}
	if err := ValidateVolumeIdentity(identity); err != nil {
		t.Fatal(err)
	}
	identity.VolumeGUID = `C:\`
	if err := ValidateVolumeIdentity(identity); err == nil || !strings.Contains(err.Error(), "InvalidVolumeGUID") {
		t.Fatalf("error = %v", err)
	}
}

func hardeningMountPointBuffer(substitute string, printName string) []byte {
	substituteBytes := hardeningUTF16Bytes(hardeningUTF16(substitute))
	printBytes := hardeningUTF16Bytes(hardeningUTF16(printName))
	pathBytes := append(append([]byte(nil), substituteBytes...), printBytes...)
	dataLength := 8 + len(pathBytes)
	raw := make([]byte, 8+dataLength)
	binary.LittleEndian.PutUint32(raw[0:4], 0xA0000003)
	binary.LittleEndian.PutUint16(raw[4:6], uint16(dataLength))
	binary.LittleEndian.PutUint16(raw[8:10], 0)
	binary.LittleEndian.PutUint16(raw[10:12], uint16(len(substituteBytes)))
	binary.LittleEndian.PutUint16(raw[12:14], uint16(len(substituteBytes)))
	binary.LittleEndian.PutUint16(raw[14:16], uint16(len(printBytes)))
	copy(raw[16:], pathBytes)
	return raw
}

func hardeningSymlinkBuffer(substitute string, printName string, flags uint32) []byte {
	substituteBytes := hardeningUTF16Bytes(hardeningUTF16(substitute))
	printBytes := hardeningUTF16Bytes(hardeningUTF16(printName))
	pathBytes := append(append([]byte(nil), substituteBytes...), printBytes...)
	dataLength := 12 + len(pathBytes)
	raw := make([]byte, 8+dataLength)
	binary.LittleEndian.PutUint32(raw[0:4], 0xA000000C)
	binary.LittleEndian.PutUint16(raw[4:6], uint16(dataLength))
	binary.LittleEndian.PutUint16(raw[8:10], 0)
	binary.LittleEndian.PutUint16(raw[10:12], uint16(len(substituteBytes)))
	binary.LittleEndian.PutUint16(raw[12:14], uint16(len(substituteBytes)))
	binary.LittleEndian.PutUint16(raw[14:16], uint16(len(printBytes)))
	binary.LittleEndian.PutUint32(raw[16:20], flags)
	copy(raw[20:], pathBytes)
	return raw
}

func hardeningUTF16(value string) []uint16 {
	units := make([]uint16, len(value))
	for index := range value {
		units[index] = uint16(value[index])
	}
	return units
}

func hardeningUTF16Bytes(units []uint16) []byte {
	encoded := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(encoded[index*2:], unit)
	}
	return encoded
}

func hardeningUTF16Base64(value string) string {
	return base64.RawURLEncoding.EncodeToString(hardeningUTF16Bytes(hardeningUTF16(value)))
}
