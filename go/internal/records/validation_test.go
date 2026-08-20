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

func TestValidateObservedAt(t *testing.T) {
	if err := ValidateObservedAt("2026-08-20T15:30:00.123456700Z"); err != nil {
		t.Fatal(err)
	}
}

func TestValidateReparseObservationKnown(t *testing.T) {
	raw := reparseTestBuffer(0xA0000003, 8)
	reparse := ReparseObservation{
		DataFormat:         ReparseDataFormatMountPoint,
		DataState:          ReparseDataStatePresent,
		RawBufferBase64URL: base64.RawURLEncoding.EncodeToString(raw),
		State:              ReparseStatePresent,
		Tag:                "0xA0000003",
		TagName:            "IO_REPARSE_TAG_MOUNT_POINT",
	}

	if err := ValidateReparseObservation(reparse); err != nil {
		t.Fatal(err)
	}
}

func TestValidateReparseObservationNotPresentRejectsTag(t *testing.T) {
	reparse := ReparseObservation{
		DataFormat: ReparseDataFormatNotApplicable,
		DataState:  ReparseDataStateNotApplicable,
		State:      ReparseStateNotPresent,
		Tag:        "0xA0000003",
		TagName:    "IO_REPARSE_TAG_MOUNT_POINT",
	}

	if err := ValidateReparseObservation(reparse); err == nil || !strings.Contains(err.Error(), "Conflict") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateReparseObservationRejectsMalformedTag(t *testing.T) {
	reparse := ReparseObservation{
		DataFormat: ReparseDataFormatNotKnown,
		DataState:  ReparseDataStateError,
		ReasonCode: "ReparseDataReadFailed",
		State:      ReparseStatePresent,
		Tag:        "0xa0000003",
		TagName:    "IO_REPARSE_TAG_MOUNT_POINT",
	}

	if err := ValidateReparseObservation(reparse); err == nil || !strings.Contains(err.Error(), "InvalidReparseTag") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateReparseObservationRejectsMismatchedKnownName(t *testing.T) {
	reparse := ReparseObservation{
		DataFormat: ReparseDataFormatNotKnown,
		DataState:  ReparseDataStateError,
		ReasonCode: "ReparseDataReadFailed",
		State:      ReparseStatePresent,
		Tag:        "0xA0000003",
		TagName:    "IO_REPARSE_TAG_SYMLINK",
	}

	if err := ValidateReparseObservation(reparse); err == nil || !strings.Contains(err.Error(), "reparse.tag_name") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateReparseObservationRejectsRawTagMismatch(t *testing.T) {
	raw := reparseTestBuffer(0xA000000C, 12)
	reparse := ReparseObservation{
		DataFormat:         ReparseDataFormatMountPoint,
		DataState:          ReparseDataStatePresent,
		RawBufferBase64URL: base64.RawURLEncoding.EncodeToString(raw),
		State:              ReparseStatePresent,
		Tag:                "0xA0000003",
		TagName:            "IO_REPARSE_TAG_MOUNT_POINT",
	}

	if err := ValidateReparseObservation(reparse); err == nil || !strings.Contains(err.Error(), "raw_buffer") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateReparseObservationUnknown(t *testing.T) {
	raw := reparseTestBuffer(0xDEADBEEF, 0)
	reparse := ReparseObservation{
		DataFormat:         ReparseDataFormatRaw,
		DataState:          ReparseDataStatePresent,
		RawBufferBase64URL: base64.RawURLEncoding.EncodeToString(raw),
		State:              ReparseStatePresent,
		Tag:                "0xDEADBEEF",
		TagName:            ReparseTagNameNotKnown,
	}

	if err := ValidateReparseObservation(reparse); err != nil {
		t.Fatal(err)
	}
}

func TestValidateReparseObservationUnknownRejectsInventedName(t *testing.T) {
	reparse := ReparseObservation{
		DataFormat: ReparseDataFormatNotKnown,
		DataState:  ReparseDataStateError,
		ReasonCode: "ReparseDataReadFailed",
		State:      ReparseStatePresent,
		Tag:        "0xDEADBEEF",
		TagName:    "SomethingElse",
	}

	if err := ValidateReparseObservation(reparse); err == nil || !strings.Contains(err.Error(), "reparse.tag_name") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateStreamInventory(t *testing.T) {
	inventory := StreamInventory{
		State: ObservationStatePresent,
		Streams: []StreamObservation{
			{
				Identity:      StreamIdentity{Kind: StreamNamedData, NameUTF16LEBase64URL: utf16b64("payload"), StreamType: "$DATA", RawNameUTF16LEBase64URL: utf16b64(":payload:$DATA")},
				LogicalSize:   "42",
				AllocatedSize: "4096",
			},
			{
				Identity:      StreamIdentity{Kind: StreamDefaultData, StreamType: "$DATA", RawNameUTF16LEBase64URL: utf16b64("::$DATA")},
				LogicalSize:   "100",
				AllocatedSize: "4096",
			},
		},
	}

	if inventory.Streams[0].Identity.RawNameUTF16LEBase64URL > inventory.Streams[1].Identity.RawNameUTF16LEBase64URL {
		inventory.Streams[0], inventory.Streams[1] = inventory.Streams[1], inventory.Streams[0]
	}
	if err := ValidateStreamInventory(inventory); err != nil {
		t.Fatal(err)
	}
}

func TestValidateStreamInventoryRejectsErrorWithStreams(t *testing.T) {
	inventory := StreamInventory{
		State:      ObservationStateError,
		ReasonCode: "StreamEnumerationFailed",
		Streams: []StreamObservation{{
			Identity:      StreamIdentity{Kind: StreamDefaultData, StreamType: "$DATA", RawNameUTF16LEBase64URL: utf16b64("::$DATA")},
			LogicalSize:   "1",
			AllocatedSize: "8",
		}},
	}
	if err := ValidateStreamInventory(inventory); err == nil || !strings.Contains(err.Error(), "Conflict") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateStreamInventoryRejectsLeadingZero(t *testing.T) {
	inventory := StreamInventory{
		State: ObservationStatePresent,
		Streams: []StreamObservation{{
			Identity:      StreamIdentity{Kind: StreamDefaultData, StreamType: "$DATA", RawNameUTF16LEBase64URL: utf16b64("::$DATA")},
			LogicalSize:   "042",
			AllocatedSize: "4096",
		}},
	}
	if err := ValidateStreamInventory(inventory); err == nil || !strings.Contains(err.Error(), "InvalidDecimal") {
		t.Fatalf("error = %v", err)
	}
}

func reparseTestBuffer(tag uint32, dataLength uint16) []byte {
	buffer := make([]byte, 8+int(dataLength))
	binary.LittleEndian.PutUint32(buffer[0:4], tag)
	binary.LittleEndian.PutUint16(buffer[4:6], dataLength)
	return buffer
}

func utf16b64(s string) string {
	b := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r > 0x7f {
			panic("test helper only supports ASCII")
		}
		b = append(b, byte(r), 0)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
