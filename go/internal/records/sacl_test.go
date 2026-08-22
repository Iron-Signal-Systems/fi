// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"encoding/binary"
	"testing"
)

func TestParseSACLDescriptorInterpretsAuditACE(t *testing.T) {
	raw := testSACLDescriptor()
	observation, err := ParseSACLDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	if observation.ACL.State != ACLStatePresent || len(observation.ACL.ACEs) != 1 {
		t.Fatalf("unexpected SACL: %#v", observation.ACL)
	}
	ace := observation.ACL.ACEs[0]
	if ace.TypeName != "SystemAudit" || ace.Mask != "1179785" || ace.SID != "S-1-1-0" {
		t.Fatalf("audit ACE = %#v", ace)
	}
	if err := ValidateSACLObservation(observation); err != nil {
		t.Fatal(err)
	}
}

func TestValidateSACLObservationRejectsMismatchedMask(t *testing.T) {
	observation, err := ParseSACLDescriptor(testSACLDescriptor())
	if err != nil {
		t.Fatal(err)
	}
	observation.ACL.ACEs[0].Mask = "1"
	if err := ValidateSACLObservation(observation); err == nil {
		t.Fatal("expected raw/interpreted mismatch")
	}
}

func TestParseSACLDescriptorDistinguishesNullAndAbsentSACL(t *testing.T) {
	nullRaw := testSACLDescriptor()
	binary.LittleEndian.PutUint32(nullRaw[12:16], 0)
	nullObservation, err := ParseSACLDescriptor(nullRaw)
	if err != nil {
		t.Fatal(err)
	}
	if nullObservation.ACL.State != ACLStateNull {
		t.Fatalf("NULL SACL state = %q", nullObservation.ACL.State)
	}

	absentRaw := testSACLDescriptor()
	control := binary.LittleEndian.Uint16(absentRaw[2:4]) &^ uint16(seSACLPresent)
	binary.LittleEndian.PutUint16(absentRaw[2:4], control)
	binary.LittleEndian.PutUint32(absentRaw[12:16], 0)
	absentObservation, err := ParseSACLDescriptor(absentRaw)
	if err != nil {
		t.Fatal(err)
	}
	if absentObservation.ACL.State != ACLStateNotPresent {
		t.Fatalf("absent SACL state = %q", absentObservation.ACL.State)
	}
}

func TestParseSACLDescriptorRejectsMalformedACE(t *testing.T) {
	raw := testSACLDescriptor()
	saclOffset := int(binary.LittleEndian.Uint32(raw[12:16]))
	firstACE := saclOffset + aclHeaderSize
	binary.LittleEndian.PutUint16(raw[firstACE+2:firstACE+4], 0xffff)
	if _, err := ParseSACLDescriptor(raw); err == nil {
		t.Fatal("expected malformed ACE rejection")
	}
}

func FuzzParseSACLDescriptor(f *testing.F) {
	f.Add(testSACLDescriptor())
	f.Add([]byte{1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, raw []byte) {
		observation, err := ParseSACLDescriptor(raw)
		if err != nil {
			return
		}
		if err := ValidateSACLObservation(observation); err != nil {
			t.Fatalf("parsed observation failed validation: %v", err)
		}
	})
}

func testSACLDescriptor() []byte {
	everyone := testSID(1, 0)
	audit := testSimpleACE(0x02, 0x00120089, everyone)
	saclOffset := securityDescriptorRelativeHeaderSize
	aclSize := aclHeaderSize + len(audit)
	raw := make([]byte, saclOffset+aclSize)

	raw[0] = 1
	binary.LittleEndian.PutUint16(raw[2:4], seSelfRelative|seSACLPresent)
	binary.LittleEndian.PutUint32(raw[12:16], uint32(saclOffset))

	raw[saclOffset] = 2
	binary.LittleEndian.PutUint16(raw[saclOffset+2:saclOffset+4], uint16(aclSize))
	binary.LittleEndian.PutUint16(raw[saclOffset+4:saclOffset+6], 1)
	copy(raw[saclOffset+aclHeaderSize:], audit)
	return raw
}
