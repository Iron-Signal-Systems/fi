// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

const inheritedACEFlag = 0x10

func TestSecurityHardeningDenyACEPreservesExactFields(t *testing.T) {
	raw := testSecurityDescriptor()
	observation, err := ParseSecurityDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}

	deny := observation.DACL.ACEs[0]
	if deny.Type != "1" || deny.TypeName != "AccessDenied" {
		t.Fatalf("deny ACE type = %#v", deny)
	}
	if deny.Mask != "1179785" { // 0x00120089
		t.Fatalf("deny ACE mask = %q", deny.Mask)
	}
	if deny.SID != "S-1-5-18" {
		t.Fatalf("deny ACE SID = %q", deny.SID)
	}
}

func TestSecurityHardeningInheritedACEFlagIsPreserved(t *testing.T) {
	raw := testSecurityDescriptor()
	daclOffset := int(binary.LittleEndian.Uint32(raw[16:20]))
	firstACE := daclOffset + aclHeaderSize
	raw[firstACE+1] = inheritedACEFlag

	observation, err := ParseSecurityDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	ace := observation.DACL.ACEs[0]
	if ace.Flags != "16" {
		t.Fatalf("flags = %q", ace.Flags)
	}

	decoded, err := base64.RawURLEncoding.DecodeString(ace.RawBase64URL)
	if err != nil {
		t.Fatal(err)
	}
	if decoded[1] != inheritedACEFlag {
		t.Fatalf("raw ACE flags = %#x", decoded[1])
	}
}

func TestSecurityHardeningEmptyDACLIsPresentNotNull(t *testing.T) {
	raw := testSecurityDescriptorWithDACL([][]byte{})
	observation, err := ParseSecurityDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	if observation.DACL.State != ACLStatePresent {
		t.Fatalf("DACL state = %q", observation.DACL.State)
	}
	if observation.DACL.Size != "8" {
		t.Fatalf("DACL size = %q", observation.DACL.Size)
	}
	if len(observation.DACL.ACEs) != 0 {
		t.Fatalf("empty DACL ACE count = %d", len(observation.DACL.ACEs))
	}
}

func TestSecurityHardeningNullDACLIsDistinctFromEmpty(t *testing.T) {
	nullRaw := testSecurityDescriptorWithDACL([][]byte{})
	binary.LittleEndian.PutUint32(nullRaw[16:20], 0)

	nullObservation, err := ParseSecurityDescriptor(nullRaw)
	if err != nil {
		t.Fatal(err)
	}
	if nullObservation.DACL.State != ACLStateNull {
		t.Fatalf("NULL DACL state = %q", nullObservation.DACL.State)
	}
	if nullObservation.DACL.Revision != "" || nullObservation.DACL.Size != "" || len(nullObservation.DACL.ACEs) != 0 {
		t.Fatalf("NULL DACL unexpectedly contains ACL fields: %#v", nullObservation.DACL)
	}
}

func TestSecurityHardeningUnsupportedACEIsRawOnly(t *testing.T) {
	unsupported := []byte{0x42, inheritedACEFlag, 0x08, 0x00, 0xde, 0xad, 0xbe, 0xef}
	raw := testSecurityDescriptorWithDACL([][]byte{unsupported})

	observation, err := ParseSecurityDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(observation.DACL.ACEs) != 1 {
		t.Fatalf("ACE count = %d", len(observation.DACL.ACEs))
	}
	ace := observation.DACL.ACEs[0]
	if ace.Type != "66" || ace.TypeName != "NotKnown" {
		t.Fatalf("unsupported ACE identity = %#v", ace)
	}
	if ace.Flags != "16" || ace.Size != "8" {
		t.Fatalf("unsupported ACE header = %#v", ace)
	}
	if ace.Mask != "" || ace.SID != "" {
		t.Fatalf("unsupported ACE was over-interpreted: %#v", ace)
	}
	if ace.RawBase64URL != base64.RawURLEncoding.EncodeToString(unsupported) {
		t.Fatalf("unsupported ACE raw bytes changed")
	}
	if err := ValidateSecurityObservation(observation); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityHardeningKnownButUnparsedCallbackObjectACEIsRawOnly(t *testing.T) {
	// ACCESS_ALLOWED_CALLBACK_OBJECT_ACE is documented, but callback ACEs may
	// contain application data after the SID. Security 1B-1 deliberately leaves
	// that variable payload raw-only rather than guessing its interpretation.
	callbackObjectACE := []byte{0x0B, 0x00, 0x08, 0x00, 0x11, 0x22, 0x33, 0x44}
	raw := testSecurityDescriptorWithDACL([][]byte{callbackObjectACE})

	observation, err := ParseSecurityDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	ace := observation.DACL.ACEs[0]
	if ace.TypeName != "AccessAllowedCallbackObject" {
		t.Fatalf("type name = %q", ace.TypeName)
	}
	if ace.Mask != "" || ace.ObjectFlags != "" || ace.ObjectTypeGUID != "" ||
		ace.InheritedObjectTypeGUID != "" || ace.SID != "" {
		t.Fatalf("callback object ACE was over-interpreted: %#v", ace)
	}
	if ace.RawBase64URL != base64.RawURLEncoding.EncodeToString(callbackObjectACE) {
		t.Fatal("callback object ACE raw bytes changed")
	}
}

func TestSecurityHardeningValidationRejectsMutatedACEFlags(t *testing.T) {
	observation, err := ParseSecurityDescriptor(testSecurityDescriptor())
	if err != nil {
		t.Fatal(err)
	}
	observation.DACL.ACEs[0].Flags = "16"
	if err := ValidateSecurityObservation(observation); err == nil {
		t.Fatal("expected raw/interpreted flag mismatch")
	}
}

func TestSecurityHardeningValidationRejectsMutatedACEOrder(t *testing.T) {
	observation, err := ParseSecurityDescriptor(testSecurityDescriptor())
	if err != nil {
		t.Fatal(err)
	}
	observation.DACL.ACEs[0], observation.DACL.ACEs[1] = observation.DACL.ACEs[1], observation.DACL.ACEs[0]
	if err := ValidateSecurityObservation(observation); err == nil {
		t.Fatal("expected raw/interpreted ACE order mismatch")
	}
}

func TestSecurityHardeningRejectsDACLACECountOutsideACL(t *testing.T) {
	raw := testSecurityDescriptorWithDACL([][]byte{})
	daclOffset := int(binary.LittleEndian.Uint32(raw[16:20]))
	binary.LittleEndian.PutUint16(raw[daclOffset+4:daclOffset+6], 1)
	if _, err := ParseSecurityDescriptor(raw); err == nil {
		t.Fatal("expected impossible ACE count rejection")
	}
}

func testSecurityDescriptorWithDACL(aces [][]byte) []byte {
	owner := testSID(5, 18)
	group := testSID(5, 32, 544)
	ownerOffset := securityDescriptorRelativeHeaderSize
	groupOffset := ownerOffset + len(owner)
	daclOffset := groupOffset + len(group)

	aclSize := aclHeaderSize
	for _, ace := range aces {
		aclSize += len(ace)
	}

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
	binary.LittleEndian.PutUint16(raw[daclOffset+4:daclOffset+6], uint16(len(aces)))
	cursor := daclOffset + aclHeaderSize
	for _, ace := range aces {
		copy(raw[cursor:], ace)
		cursor += len(ace)
	}
	return raw
}
