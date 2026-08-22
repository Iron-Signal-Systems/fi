// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestValidateSMBShareSnapshot(t *testing.T) {
	security, err := ParseSecurityDescriptor(testSecurityDescriptor())
	if err != nil {
		t.Fatal(err)
	}

	snapshot := SMBShareSnapshot{
		ObservedAt:       "2026-08-22T09:45:00.000000000Z",
		CollectionMethod: SMBShareCollectionWindowsNetShareEnum502,
		Shares: []SMBShareObservation{
			testSMBShare("ADMIN$", `C:\\Windows`, 0x80000000, security),
			testSMBShare("C$", `C:\\`, 0x80000000, security),
		},
	}
	if err := ValidateSMBShareSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
}

func TestValidateSMBShareSnapshotRejectsUnsortedShares(t *testing.T) {
	security, err := ParseSecurityDescriptor(testSecurityDescriptor())
	if err != nil {
		t.Fatal(err)
	}
	snapshot := SMBShareSnapshot{
		ObservedAt:       "2026-08-22T09:45:00.000000000Z",
		CollectionMethod: SMBShareCollectionWindowsNetShareEnum502,
		Shares: []SMBShareObservation{
			testSMBShare("Z", `C:\\Z`, 0, security),
			testSMBShare("A", `C:\\A`, 0, security),
		},
	}
	if err := ValidateSMBShareSnapshot(snapshot); err == nil {
		t.Fatal("expected unsorted share rejection")
	}
}

func TestValidateSMBShareObservationRejectsTypeMismatch(t *testing.T) {
	security, err := ParseSecurityDescriptor(testSecurityDescriptor())
	if err != nil {
		t.Fatal(err)
	}
	share := testSMBShare("data", `D:\\Data`, 0, security)
	share.TypeName = SMBShareTypeIPC
	if err := ValidateSMBShareObservation(share); err == nil {
		t.Fatal("expected share type mismatch")
	}
}

func TestValidateSMBShareObservationRejectsDisplayMismatch(t *testing.T) {
	security, err := ParseSecurityDescriptor(testSecurityDescriptor())
	if err != nil {
		t.Fatal(err)
	}
	share := testSMBShare("data", `D:\\Data`, 0, security)
	share.NameDisplay = "other"
	if err := ValidateSMBShareObservation(share); err == nil {
		t.Fatal("expected share display mismatch")
	}
}

func TestClassifySMBShareType(t *testing.T) {
	name, special, temporary := ClassifySMBShareType(0xC0000003)
	if name != SMBShareTypeIPC || !special || !temporary {
		t.Fatalf("classification = %q special=%t temporary=%t", name, special, temporary)
	}
}

func testSMBShare(name, path string, rawType uint32, security SecurityObservation) SMBShareObservation {
	typeName, special, temporary := ClassifySMBShareType(rawType)
	return SMBShareObservation{
		NameDisplay:               name,
		NameUTF16LEBase64URL:      testUTF16LEBase64URL(name),
		TypeRaw:                   uint32Decimal(rawType),
		TypeName:                  typeName,
		Special:                   special,
		Temporary:                 temporary,
		LocalPathDisplay:          path,
		LocalPathUTF16LEBase64URL: testUTF16LEBase64URL(path),
		PermissionsRaw:            "0",
		MaxUsesRaw:                "4294967295",
		CurrentUses:               "0",
		Security:                  security,
	}
}

func testUTF16LEBase64URL(value string) string {
	units := utf16.Encode([]rune(value))
	raw := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(raw[index*2:], unit)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func uint32Decimal(value uint32) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	var buf [10]byte
	position := len(buf)
	for value > 0 {
		position--
		buf[position] = digits[value%10]
		value /= 10
	}
	return string(buf[position:])
}
