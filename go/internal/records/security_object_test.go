// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

const (
	successfulAccessACEFlag = 0x40
	failedAccessACEFlag     = 0x80
)

func TestSecurityObjectACEParsesBothGUIDsAndSID(t *testing.T) {
	objectType := testGUIDBytes(0x00112233, 0x4455, 0x6677, [8]byte{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	inheritedType := testGUIDBytes(0x10213243, 0x5465, 0x7687, [8]byte{0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f})
	sid := testSID(5, 32, 544)
	ace := testObjectACE(
		0x05,
		inheritedACEFlag,
		0x00000100,
		aceObjectTypePresent|aceInheritedObjectTypePresent,
		objectType,
		inheritedType,
		sid,
	)

	observation, err := ParseSecurityDescriptor(testSecurityDescriptorWithDACLRevision(4, [][]byte{ace}))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSecurityObservation(observation); err != nil {
		t.Fatal(err)
	}

	got := observation.DACL.ACEs[0]
	if got.TypeName != "AccessAllowedObject" || got.Flags != "16" || got.Mask != "256" {
		t.Fatalf("object ACE fixed fields = %#v", got)
	}
	if got.ObjectFlags != "3" {
		t.Fatalf("object flags = %q", got.ObjectFlags)
	}
	if got.ObjectTypeGUID != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatalf("object GUID = %q", got.ObjectTypeGUID)
	}
	if got.InheritedObjectTypeGUID != "10213243-5465-7687-98a9-bacbdcedfe0f" {
		t.Fatalf("inherited object GUID = %q", got.InheritedObjectTypeGUID)
	}
	if got.SID != "S-1-5-32-544" {
		t.Fatalf("SID = %q", got.SID)
	}
	if got.RawBase64URL != base64.RawURLEncoding.EncodeToString(ace) {
		t.Fatal("object ACE raw bytes changed")
	}
}

func TestSecurityObjectACENoGUIDsUsesImmediateSID(t *testing.T) {
	ace := testObjectACE(0x06, 0, 0x00120089, 0, nil, nil, testSID(5, 18))
	observation, err := ParseSecurityDescriptor(testSecurityDescriptorWithDACLRevision(4, [][]byte{ace}))
	if err != nil {
		t.Fatal(err)
	}

	got := observation.DACL.ACEs[0]
	if got.TypeName != "AccessDeniedObject" || got.Mask != "1179785" || got.ObjectFlags != "0" {
		t.Fatalf("object ACE = %#v", got)
	}
	if got.ObjectTypeGUID != "" || got.InheritedObjectTypeGUID != "" {
		t.Fatalf("unexpected GUIDs: %#v", got)
	}
	if got.SID != "S-1-5-18" {
		t.Fatalf("SID = %q", got.SID)
	}
}

func TestSecurityAuditObjectACEParsesObjectTypeAndSID(t *testing.T) {
	objectType := testGUIDBytes(0xaabbccdd, 0xeeff, 0x1020, [8]byte{0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0})
	ace := testObjectACE(
		0x07,
		successfulAccessACEFlag|failedAccessACEFlag,
		0x00000001,
		aceObjectTypePresent,
		objectType,
		nil,
		testSID(1, 0),
	)
	observation, err := ParseSecurityDescriptor(testSecurityDescriptorWithDACLRevision(4, [][]byte{ace}))
	if err != nil {
		t.Fatal(err)
	}

	got := observation.DACL.ACEs[0]
	if got.TypeName != "SystemAuditObject" || got.Flags != "192" || got.Mask != "1" || got.ObjectFlags != "1" {
		t.Fatalf("audit object ACE = %#v", got)
	}
	if got.ObjectTypeGUID != "aabbccdd-eeff-1020-3040-5060708090a0" {
		t.Fatalf("object GUID = %q", got.ObjectTypeGUID)
	}
	if got.InheritedObjectTypeGUID != "" || got.SID != "S-1-1-0" {
		t.Fatalf("audit object ACE variable fields = %#v", got)
	}
}

func TestSecurityAuditACEParsesMaskAndSID(t *testing.T) {
	ace := testSimpleACEWithFlags(0x02, successfulAccessACEFlag|failedAccessACEFlag, 0x00120089, testSID(1, 0))
	observation, err := ParseSecurityDescriptor(testSecurityDescriptorWithDACL([][]byte{ace}))
	if err != nil {
		t.Fatal(err)
	}
	got := observation.DACL.ACEs[0]
	if got.TypeName != "SystemAudit" || got.Flags != "192" || got.Mask != "1179785" || got.SID != "S-1-1-0" {
		t.Fatalf("audit ACE = %#v", got)
	}
}

func TestSecurityMandatoryLabelACEParsesPolicyAndSID(t *testing.T) {
	ace := testSimpleACEWithFlags(0x11, 0, 0x00000001, testSID(16, 8192))
	observation, err := ParseSecurityDescriptor(testSecurityDescriptorWithDACL([][]byte{ace}))
	if err != nil {
		t.Fatal(err)
	}
	got := observation.DACL.ACEs[0]
	if got.TypeName != "MandatoryLabel" || got.Mask != "1" || got.SID != "S-1-16-8192" {
		t.Fatalf("mandatory label ACE = %#v", got)
	}
}

func TestSecurityObjectACERejectsTruncatedObjectGUID(t *testing.T) {
	ace := make([]byte, 20)
	ace[0] = 0x05
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
	binary.LittleEndian.PutUint32(ace[4:8], 1)
	binary.LittleEndian.PutUint32(ace[8:12], aceObjectTypePresent)
	if _, err := ParseSecurityDescriptor(testSecurityDescriptorWithDACLRevision(4, [][]byte{ace})); err == nil {
		t.Fatal("expected truncated ObjectType GUID rejection")
	}
}

func TestSecurityObjectACEValidationRejectsMutatedGUID(t *testing.T) {
	objectType := testGUIDBytes(0x00112233, 0x4455, 0x6677, [8]byte{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	ace := testObjectACE(0x05, 0, 1, aceObjectTypePresent, objectType, nil, testSID(1, 0))
	observation, err := ParseSecurityDescriptor(testSecurityDescriptorWithDACLRevision(4, [][]byte{ace}))
	if err != nil {
		t.Fatal(err)
	}
	observation.DACL.ACEs[0].ObjectTypeGUID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
	if err := ValidateSecurityObservation(observation); err == nil {
		t.Fatal("expected raw/interpreted object GUID mismatch")
	}
}

func testObjectACE(aceType, aceFlags byte, mask, objectFlags uint32, objectType, inheritedType, sid []byte) []byte {
	size := 12 + len(sid)
	if objectFlags&aceObjectTypePresent != 0 {
		size += 16
	}
	if objectFlags&aceInheritedObjectTypePresent != 0 {
		size += 16
	}

	raw := make([]byte, size)
	raw[0] = aceType
	raw[1] = aceFlags
	binary.LittleEndian.PutUint16(raw[2:4], uint16(size))
	binary.LittleEndian.PutUint32(raw[4:8], mask)
	binary.LittleEndian.PutUint32(raw[8:12], objectFlags)

	cursor := 12
	if objectFlags&aceObjectTypePresent != 0 {
		copy(raw[cursor:cursor+16], objectType)
		cursor += 16
	}
	if objectFlags&aceInheritedObjectTypePresent != 0 {
		copy(raw[cursor:cursor+16], inheritedType)
		cursor += 16
	}
	copy(raw[cursor:], sid)
	return raw
}

func testSimpleACEWithFlags(aceType, flags byte, mask uint32, sid []byte) []byte {
	raw := testSimpleACE(aceType, mask, sid)
	raw[1] = flags
	return raw
}

func testSecurityDescriptorWithDACLRevision(revision byte, aces [][]byte) []byte {
	raw := testSecurityDescriptorWithDACL(aces)
	daclOffset := int(binary.LittleEndian.Uint32(raw[16:20]))
	raw[daclOffset] = revision
	return raw
}

func testGUIDBytes(data1 uint32, data2, data3 uint16, data4 [8]byte) []byte {
	raw := make([]byte, 16)
	binary.LittleEndian.PutUint32(raw[0:4], data1)
	binary.LittleEndian.PutUint16(raw[4:6], data2)
	binary.LittleEndian.PutUint16(raw[6:8], data3)
	copy(raw[8:], data4[:])
	return raw
}
