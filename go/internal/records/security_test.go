// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"encoding/binary"
	"testing"
)

func TestParseSecurityDescriptorInterpretsOrderedDACL(t *testing.T) {
	raw := testSecurityDescriptor()
	observation, err := ParseSecurityDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	if observation.OwnerSID != "S-1-5-18" {
		t.Fatalf("owner = %q", observation.OwnerSID)
	}
	if observation.PrimaryGroupSID != "S-1-5-32-544" {
		t.Fatalf("group = %q", observation.PrimaryGroupSID)
	}
	if observation.DACL.State != ACLStatePresent || len(observation.DACL.ACEs) != 2 {
		t.Fatalf("unexpected DACL: %#v", observation.DACL)
	}
	if observation.DACL.ACEs[0].TypeName != "AccessDenied" || observation.DACL.ACEs[0].SID != "S-1-5-18" {
		t.Fatalf("ACE[0] = %#v", observation.DACL.ACEs[0])
	}
	if observation.DACL.ACEs[1].TypeName != "AccessAllowed" || observation.DACL.ACEs[1].SID != "S-1-5-32-544" {
		t.Fatalf("ACE[1] = %#v", observation.DACL.ACEs[1])
	}
	if err := ValidateSecurityObservation(observation); err != nil {
		t.Fatal(err)
	}
}

func TestValidateSecurityObservationRejectsMismatchedMask(t *testing.T) {
	observation, err := ParseSecurityDescriptor(testSecurityDescriptor())
	if err != nil {
		t.Fatal(err)
	}
	observation.DACL.ACEs[1].Mask = "1"
	if err := ValidateSecurityObservation(observation); err == nil {
		t.Fatal("expected raw/interpreted mismatch")
	}
}

func TestParseSecurityDescriptorDistinguishesNullAndAbsentDACL(t *testing.T) {
	nullRaw := testSecurityDescriptor()
	binary.LittleEndian.PutUint32(nullRaw[16:20], 0)
	nullObservation, err := ParseSecurityDescriptor(nullRaw)
	if err != nil {
		t.Fatal(err)
	}
	if nullObservation.DACL.State != ACLStateNull {
		t.Fatalf("NULL DACL state = %q", nullObservation.DACL.State)
	}

	absentRaw := testSecurityDescriptor()
	control := binary.LittleEndian.Uint16(absentRaw[2:4]) &^ uint16(seDACLPresent)
	binary.LittleEndian.PutUint16(absentRaw[2:4], control)
	binary.LittleEndian.PutUint32(absentRaw[16:20], 0)
	absentObservation, err := ParseSecurityDescriptor(absentRaw)
	if err != nil {
		t.Fatal(err)
	}
	if absentObservation.DACL.State != ACLStateNotPresent {
		t.Fatalf("absent DACL state = %q", absentObservation.DACL.State)
	}
}

func TestParseSecurityDescriptorRejectsMalformedACE(t *testing.T) {
	raw := testSecurityDescriptor()
	daclOffset := int(binary.LittleEndian.Uint32(raw[16:20]))
	firstACE := daclOffset + aclHeaderSize
	binary.LittleEndian.PutUint16(raw[firstACE+2:firstACE+4], 0xffff)
	if _, err := ParseSecurityDescriptor(raw); err == nil {
		t.Fatal("expected malformed ACE rejection")
	}
}

func FuzzParseSecurityDescriptor(f *testing.F) {
	f.Add(testSecurityDescriptor())
	f.Add([]byte{1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		observation, err := ParseSecurityDescriptor(raw)
		if err != nil {
			return
		}
		if err := ValidateSecurityObservation(observation); err != nil {
			t.Fatalf("parsed observation failed validation: %v", err)
		}
	})
}

func testSecurityDescriptor() []byte {
	owner := testSID(5, 18)
	group := testSID(5, 32, 544)
	deny := testSimpleACE(0x01, 0x00120089, owner)
	allow := testSimpleACE(0x00, 0x001f01ff, group)

	ownerOffset := securityDescriptorRelativeHeaderSize
	groupOffset := ownerOffset + len(owner)
	daclOffset := groupOffset + len(group)
	aclSize := aclHeaderSize + len(deny) + len(allow)
	raw := make([]byte, daclOffset+aclSize)

	raw[0] = 1
	binary.LittleEndian.PutUint16(raw[2:4], seSelfRelative|seDACLPresent)
	binary.LittleEndian.PutUint32(raw[4:8], uint32(ownerOffset))
	binary.LittleEndian.PutUint32(raw[8:12], uint32(groupOffset))
	binary.LittleEndian.PutUint32(raw[16:20], uint32(daclOffset))
	copy(raw[ownerOffset:], owner)
	copy(raw[groupOffset:], group)

	raw[daclOffset] = 2
	binary.LittleEndian.PutUint16(raw[daclOffset+2:daclOffset+4], uint16(aclSize))
	binary.LittleEndian.PutUint16(raw[daclOffset+4:daclOffset+6], 2)
	copy(raw[daclOffset+aclHeaderSize:], deny)
	copy(raw[daclOffset+aclHeaderSize+len(deny):], allow)
	return raw
}

func testSID(authority uint64, subAuthorities ...uint32) []byte {
	raw := make([]byte, 8+len(subAuthorities)*4)
	raw[0] = 1
	raw[1] = byte(len(subAuthorities))
	for index := 0; index < 6; index++ {
		shift := uint((5 - index) * 8)
		raw[2+index] = byte(authority >> shift)
	}
	for index, subAuthority := range subAuthorities {
		start := 8 + index*4
		binary.LittleEndian.PutUint32(raw[start:start+4], subAuthority)
	}
	return raw
}

func testSimpleACE(aceType byte, mask uint32, sid []byte) []byte {
	raw := make([]byte, 8+len(sid))
	raw[0] = aceType
	binary.LittleEndian.PutUint16(raw[2:4], uint16(len(raw)))
	binary.LittleEndian.PutUint32(raw[4:8], mask)
	copy(raw[8:], sid)
	return raw
}
