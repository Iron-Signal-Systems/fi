// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package ntfs

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"testing"
)

func TestSplitNTFSFileID(t *testing.T) {
	var fileID [16]byte
	const record uint64 = 0x0000123456789ABC
	const sequence uint64 = 0xBEEF

	binary.LittleEndian.PutUint64(fileID[:8], record|(sequence<<48))

	gotRecord, gotSequence, err := splitNTFSFileID(fileID)
	if err != nil {
		t.Fatal(err)
	}
	if gotRecord != record || gotSequence != uint16(sequence) {
		t.Fatalf("got record=%x sequence=%x", gotRecord, gotSequence)
	}
}

func TestSplitNTFSFileIDRejectsHighBits(t *testing.T) {
	var fileID [16]byte
	fileID[8] = 1

	if _, _, err := splitNTFSFileID(fileID); err == nil {
		t.Fatal("expected high-bit rejection")
	}
}

func TestFiletimeToCanonical(t *testing.T) {
	got, err := filetimeToCanonical(116444736000000000)
	if err != nil {
		t.Fatal(err)
	}
	if got != "1970-01-01T00:00:00.000000000Z" {
		t.Fatalf("got %s", got)
	}

	got, err = filetimeToCanonical(116444736000000001)
	if err != nil {
		t.Fatal(err)
	}
	if got != "1970-01-01T00:00:00.000000100Z" {
		t.Fatalf("got %s", got)
	}
}

func TestUTF16LEBase64URLPreservesCodeUnits(t *testing.T) {
	units := []uint16{'A', 0xD800, 'B'}

	encoded := utf16LEBase64URL(units)
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}

	for index, want := range units {
		if got := binary.LittleEndian.Uint16(decoded[index*2:]); got != want {
			t.Fatalf("unit %d = %04x, want %04x", index, got, want)
		}
	}
}

func TestStreamIdentityParsing(t *testing.T) {
	defaultStream := streamIdentityFromWindowsName(asciiUTF16(`::$DATA`))
	if defaultStream.Kind != records.StreamDefaultData ||
		defaultStream.StreamType != "$DATA" ||
		defaultStream.NameUTF16LEBase64URL != "" {
		t.Fatalf("default = %+v", defaultStream)
	}

	named := streamIdentityFromWindowsName(asciiUTF16(`:payload:$DATA`))
	if named.Kind != records.StreamNamedData ||
		named.StreamType != "$DATA" ||
		named.NameUTF16LEBase64URL == "" {
		t.Fatalf("named = %+v", named)
	}

	other := streamIdentityFromWindowsName(asciiUTF16(`:$I30:$INDEX_ALLOCATION`))
	if other.Kind != records.StreamOther ||
		other.StreamType != "$INDEX_ALLOCATION" {
		t.Fatalf("other = %+v", other)
	}
}

func TestObservationConsistencyCompleteRejectsStreamError(t *testing.T) {
	observation := Observation{
		ObservationStatus: records.ObservationComplete,
		StreamInventory: records.StreamInventory{
			State:      records.ObservationStateError,
			ReasonCode: "StreamEnumerationFailed",
		},
		Warnings: []records.ObservationWarning{{Code: "StreamEnumerationFailed"}},
	}
	if err := validateObservationConsistency(observation); err == nil {
		t.Fatal("expected conflict")
	}
}

func TestObservationConsistencyPartialRequiresPartialCondition(t *testing.T) {
	observation := Observation{
		ObservationStatus: records.ObservationPartial,
		StreamInventory: records.StreamInventory{
			State: records.ObservationStatePresent,
		},
	}
	if err := validateObservationConsistency(observation); err == nil {
		t.Fatal("expected conflict")
	}
}

func TestObservationConsistencyChangedRequiresMetadataWarning(t *testing.T) {
	observation := Observation{
		ObservationStatus: records.ObservationChangedDuringCollection,
		StreamInventory: records.StreamInventory{
			State: records.ObservationStatePresent,
		},
	}
	if err := validateObservationConsistency(observation); err == nil {
		t.Fatal("expected conflict")
	}
}

func TestObservationConsistencyReplacedRequiresReplacementWarning(t *testing.T) {
	observation := Observation{
		ObservationStatus: records.ObservationReplacedDuringCollection,
		StreamInventory: records.StreamInventory{
			State: records.ObservationStatePresent,
		},
	}
	if err := validateObservationConsistency(observation); err == nil {
		t.Fatal("expected conflict")
	}
}

func TestObservationConsistencyValidComplete(t *testing.T) {
	observation := Observation{
		ObservationStatus: records.ObservationComplete,
		StreamInventory: records.StreamInventory{
			State: records.ObservationStatePresent,
		},
		Reparse: records.ReparseObservation{
			DataFormat: records.ReparseDataFormatNotApplicable,
			DataState:  records.ReparseDataStateNotApplicable,
			State:      records.ReparseStateNotPresent,
		},
	}
	if err := validateObservationConsistency(observation); err != nil {
		t.Fatal(err)
	}
}

func TestParentLocalAbsolutePath(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{`C:\`, `C:\`},
		{`C:\one`, `C:\`},
		{`C:\one\two`, `C:\one`},
		{`C:\one\two\`, `C:\one`},
		{`\\?\C:\`, `\\?\C:\`},
		{`\\?\C:\one`, `\\?\C:\`},
		{`\\?\C:\one\two`, `\\?\C:\one`},
	}

	for _, test := range tests {
		got, err := parentLocalAbsolutePath(asciiUTF16(test.input))
		if err != nil {
			t.Fatalf("parentLocalAbsolutePath(%q): %v", test.input, err)
		}
		if stringFromASCIIUTF16(got) != test.want {
			t.Fatalf("parentLocalAbsolutePath(%q) = %q, want %q", test.input, stringFromASCIIUTF16(got), test.want)
		}
	}
}

func stringFromASCIIUTF16(value []uint16) string {
	result := make([]byte, len(value))
	for index := range value {
		result[index] = byte(value[index])
	}
	return string(result)
}

func asciiUTF16(value string) []uint16 {
	units := make([]uint16, len(value))
	for index := range value {
		units[index] = uint16(value[index])
	}
	return units
}

func TestLocalAbsolutePathValidation(t *testing.T) {
	accepted := []string{
		`C:\Data\object.txt`,
		`\\?\C:\Data\object.txt`,
	}
	for _, value := range accepted {
		if err := validateLocalAbsolutePath(asciiUTF16(value)); err != nil {
			t.Fatalf("validateLocalAbsolutePath(%q) = %v", value, err)
		}
	}

	rejected := []string{
		`Data\object.txt`,
		`C:object.txt`,
		`\\server\share\object.txt`,
		`\\?\UNC\server\share\object.txt`,
		`\\?\Volume{11111111-1111-1111-1111-111111111111}\object.txt`,
		`\\?\GLOBALROOT\Device\HarddiskVolume1\object.txt`,
		`\\.\C:\Data\object.txt`,
		`\\.\pipe\fi`,
	}
	for _, value := range rejected {
		err := validateLocalAbsolutePath(asciiUTF16(value))
		if !errors.Is(err, ErrUnsafePathForm) {
			t.Fatalf("validateLocalAbsolutePath(%q) = %v, want ErrUnsafePathForm", value, err)
		}
	}
}

func TestLocalAbsolutePathRejectsNamedStream(t *testing.T) {
	streamPaths := []string{
		`C:\Data\object.txt:payload`,
		`\\?\C:\Data\object.txt:Zone.Identifier`,
	}
	for _, value := range streamPaths {
		err := validateLocalAbsolutePath(asciiUTF16(value))
		if !errors.Is(err, ErrStreamQualifiedPath) {
			t.Fatalf("validateLocalAbsolutePath(%q) = %v, want ErrStreamQualifiedPath", value, err)
		}
	}
}

func TestHandleDerivedContainment(t *testing.T) {
	root := asciiUTF16(`\\?\Volume{11111111-1111-1111-1111-111111111111}\Data`)
	tests := []struct {
		target string
		want   bool
	}{
		{`\\?\Volume{11111111-1111-1111-1111-111111111111}\Data`, true},
		{`\\?\Volume{11111111-1111-1111-1111-111111111111}\Data\object.txt`, true},
		{`\\?\Volume{11111111-1111-1111-1111-111111111111}\Database\object.txt`, false},
		{`\\?\Volume{22222222-2222-2222-2222-222222222222}\Data\object.txt`, false},
	}
	for _, test := range tests {
		if got := pathContainedBy(root, asciiUTF16(test.target)); got != test.want {
			t.Fatalf("pathContainedBy(%q) = %v, want %v", test.target, got, test.want)
		}
	}
}

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
