// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestGovernedRootDrive(t *testing.T) {
	for input, want := range map[string]string{
		`C:\Data`:     "C",
		`c:\Data`:     "c",
		`\\?\D:\Data`: "D",
	} {
		got, err := governedRootDrive(input)
		if err != nil {
			t.Fatalf("governedRootDrive(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("governedRootDrive(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestGovernedRootDriveRejectsUNC(t *testing.T) {
	if _, err := governedRootDrive(`\\server\share\data`); err == nil {
		t.Fatal("expected UNC root rejection")
	}
}

func TestIdentityFromReference(t *testing.T) {
	reference := uint64(144588) | uint64(8)<<48
	identity := identityFromReference(reference)
	if identity.FileReferenceNumber != "144588" || identity.SequenceNumber != "8" {
		t.Fatalf("identity = %+v", identity)
	}
}

func TestReasonNames(t *testing.T) {
	got := reasonNames(0x00000100 | 0x00000800 | 0x80000000)
	want := []string{"Close", "FileCreate", "SecurityChange"}
	if len(got) != len(want) {
		t.Fatalf("reasonNames = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("reasonNames[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestParseReadBufferV2(t *testing.T) {
	nameUnits := utf16.Encode([]rune("file.txt"))
	nameBytes := make([]byte, len(nameUnits)*2)
	for i, unit := range nameUnits {
		binary.LittleEndian.PutUint16(nameBytes[i*2:], unit)
	}

	recordLength := usnV2HeaderSize + len(nameBytes)
	if rem := recordLength % 8; rem != 0 {
		recordLength += 8 - rem
	}
	buffer := make([]byte, 8+recordLength)
	binary.LittleEndian.PutUint64(buffer[:8], 200)
	record := buffer[8:]
	binary.LittleEndian.PutUint32(record[0:4], uint32(recordLength))
	binary.LittleEndian.PutUint16(record[4:6], 2)
	binary.LittleEndian.PutUint16(record[6:8], 0)
	binary.LittleEndian.PutUint64(record[8:16], uint64(144588)|uint64(8)<<48)
	binary.LittleEndian.PutUint64(record[16:24], uint64(103695)|uint64(8)<<48)
	binary.LittleEndian.PutUint64(record[24:32], 150)
	binary.LittleEndian.PutUint64(record[32:40], 134000000000000000)
	binary.LittleEndian.PutUint32(record[40:44], 0x00000100)
	binary.LittleEndian.PutUint32(record[48:52], 7)
	binary.LittleEndian.PutUint32(record[52:56], 32)
	binary.LittleEndian.PutUint16(record[56:58], uint16(len(nameBytes)))
	binary.LittleEndian.PutUint16(record[58:60], usnV2HeaderSize)
	copy(record[usnV2HeaderSize:], nameBytes)

	next, changes, err := parseReadBuffer(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if next != 200 || len(changes) != 1 {
		t.Fatalf("next=%d changes=%d", next, len(changes))
	}
	if changes[0].FileIdentity.FileReferenceNumber != "144588" ||
		changes[0].FileIdentity.SequenceNumber != "8" ||
		changes[0].ParentIdentity.FileReferenceNumber != "103695" {
		t.Fatalf("unexpected identities: %+v", changes[0])
	}
}

func TestParseReadBufferRejectsUnsupportedVersion(t *testing.T) {
	buffer := make([]byte, 8+usnV2HeaderSize)
	binary.LittleEndian.PutUint64(buffer[:8], 200)
	binary.LittleEndian.PutUint32(buffer[8:12], usnV2HeaderSize)
	binary.LittleEndian.PutUint16(buffer[12:14], 3)
	if _, _, err := parseReadBuffer(buffer); err == nil {
		t.Fatal("expected unsupported-version error")
	}
}
