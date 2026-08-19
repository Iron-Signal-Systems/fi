// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package ntfs

import (
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
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
	if defaultStream.Kind != records.StreamDefaultData || defaultStream.StreamType != "$DATA" || defaultStream.NameUTF16LEBase64URL != "" {
		t.Fatalf("default = %+v", defaultStream)
	}
	named := streamIdentityFromWindowsName(asciiUTF16(`:payload:$DATA`))
	if named.Kind != records.StreamNamedData || named.StreamType != "$DATA" || named.NameUTF16LEBase64URL == "" {
		t.Fatalf("named = %+v", named)
	}
	other := streamIdentityFromWindowsName(asciiUTF16(`:$I30:$INDEX_ALLOCATION`))
	if other.Kind != records.StreamOther || other.StreamType != "$INDEX_ALLOCATION" {
		t.Fatalf("other = %+v", other)
	}
}
