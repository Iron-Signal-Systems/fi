// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"encoding/binary"
	"testing"
)

func TestEnterpriseCAsPublishingAllRequiresSameCA(
	t *testing.T,
) {
	cas := []enterpriseCertificateAuthorityState{
		{
			Configuration: `ca-a.example.test\CA-A`,
			Templates: []string{
				fiTransportClientTemplateName,
			},
		},
		{
			Configuration: `ca-b.example.test\CA-B`,
			Templates: []string{
				fiBatchSigningTemplateName,
			},
		},
	}

	common := enterpriseCAsPublishingAll(
		cas,
		[]string{
			fiTransportClientTemplateName,
			fiBatchSigningTemplateName,
		},
	)
	if len(common) != 0 {
		t.Fatalf(
			"common CA count=%d want=0",
			len(common),
		)
	}

	cas[0].Templates = append(
		cas[0].Templates,
		fiBatchSigningTemplateName,
	)
	common = enterpriseCAsPublishingAll(
		cas,
		[]string{
			fiTransportClientTemplateName,
			fiBatchSigningTemplateName,
		},
	)
	if len(common) != 1 {
		t.Fatalf(
			"common CA count=%d want=1",
			len(common),
		)
	}
	if common[0].Configuration != cas[0].Configuration {
		t.Fatalf(
			"common CA=%q want=%q",
			common[0].Configuration,
			cas[0].Configuration,
		)
	}
}

func TestCertificateEnrollACEObjectSpecificAllow(
	t *testing.T,
) {
	sid := testSIDBytes(
		5,
		[]uint32{21, 100, 200, 300, 400},
	)

	ace := make(
		[]byte,
		12+16+len(sid),
	)
	ace[0] = accessAllowedObjectACE
	binary.LittleEndian.PutUint16(
		ace[2:4],
		uint16(len(ace)),
	)
	binary.LittleEndian.PutUint32(
		ace[4:8],
		adsRightDSControlAccess,
	)
	binary.LittleEndian.PutUint32(
		ace[8:12],
		aceObjectTypePresent,
	)
	copy(
		ace[12:28],
		certificateEnrollmentExtendedRightGUID[:],
	)
	copy(
		ace[28:],
		sid,
	)

	applies, observedSID, mask, err := certificateEnrollACE(
		ace,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !applies {
		t.Fatal("certificate enrollment ACE did not apply")
	}
	if mask != adsRightDSControlAccess {
		t.Fatalf(
			"mask=0x%08X want=0x%08X",
			mask,
			adsRightDSControlAccess,
		)
	}
	if observedSID != "S-1-5-21-100-200-300-400" {
		t.Fatalf(
			"SID=%q",
			observedSID,
		)
	}
}

func TestCertificateEnrollACEIgnoresDifferentExtendedRight(
	t *testing.T,
) {
	sid := testSIDBytes(
		5,
		[]uint32{32, 544},
	)

	ace := make(
		[]byte,
		12+16+len(sid),
	)
	ace[0] = accessAllowedObjectACE
	binary.LittleEndian.PutUint16(
		ace[2:4],
		uint16(len(ace)),
	)
	binary.LittleEndian.PutUint32(
		ace[4:8],
		adsRightDSControlAccess,
	)
	binary.LittleEndian.PutUint32(
		ace[8:12],
		aceObjectTypePresent,
	)
	for index := 12; index < 28; index++ {
		ace[index] = 0xAA
	}
	copy(
		ace[28:],
		sid,
	)

	applies, _, _, err := certificateEnrollACE(
		ace,
	)
	if err != nil {
		t.Fatal(err)
	}
	if applies {
		t.Fatal("unrelated extended-right ACE applied to certificate enrollment")
	}
}

func TestSecurityDescriptorTemplateReadAndEnroll(
	t *testing.T,
) {
	sid := "S-1-5-32-544"
	sidBytes := testSIDBytes(
		5,
		[]uint32{32, 544},
	)

	descriptor := testSecurityDescriptor(
		testSimpleACE(
			accessAllowedACE,
			certificateTemplateGenericReadMask,
			sidBytes,
		),
		testSimpleACE(
			accessAllowedACE,
			adsRightDSControlAccess,
			sidBytes,
		),
	)

	allow := map[string]struct{}{
		sid: {},
	}
	deny := map[string]struct{}{
		sid: {},
	}

	readAllowed, err := securityDescriptorAllowsCertificateTemplateRead(
		descriptor,
		allow,
		deny,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !readAllowed {
		t.Fatal("template Read should be allowed")
	}

	enrollAllowed, err := securityDescriptorAllowsCertificateEnrollment(
		descriptor,
		allow,
		deny,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !enrollAllowed {
		t.Fatal("template Enroll should be allowed")
	}
}

func TestSecurityDescriptorTemplateReadRequiresCompleteGenericRead(
	t *testing.T,
) {
	sid := "S-1-5-32-544"
	sidBytes := testSIDBytes(
		5,
		[]uint32{32, 544},
	)

	descriptor := testSecurityDescriptor(
		testSimpleACE(
			accessAllowedACE,
			adsRightReadControl|adsRightDSReadProp,
			sidBytes,
		),
	)

	allowed, err := securityDescriptorAllowsCertificateTemplateRead(
		descriptor,
		map[string]struct{}{
			sid: {},
		},
		map[string]struct{}{
			sid: {},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("incomplete generic Read mask unexpectedly accepted")
	}
}

func TestSecurityDescriptorTemplateReadDenyWins(
	t *testing.T,
) {
	sid := "S-1-5-32-544"
	sidBytes := testSIDBytes(
		5,
		[]uint32{32, 544},
	)

	descriptor := testSecurityDescriptor(
		testSimpleACE(
			accessDeniedACE,
			adsRightDSReadProp,
			sidBytes,
		),
		testSimpleACE(
			accessAllowedACE,
			certificateTemplateGenericReadMask,
			sidBytes,
		),
	)

	allowed, err := securityDescriptorAllowsCertificateTemplateRead(
		descriptor,
		map[string]struct{}{
			sid: {},
		},
		map[string]struct{}{
			sid: {},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("template Read deny did not win")
	}
}

func TestSecurityDescriptorEnrollmentDenyWins(
	t *testing.T,
) {
	sid := "S-1-5-32-544"
	sidBytes := testSIDBytes(
		5,
		[]uint32{32, 544},
	)

	allowACE := testSimpleACE(
		accessAllowedACE,
		adsRightDSControlAccess,
		sidBytes,
	)
	denyACE := testSimpleACE(
		accessDeniedACE,
		adsRightDSControlAccess,
		sidBytes,
	)

	descriptor := testSecurityDescriptor(
		denyACE,
		allowACE,
	)

	allow := map[string]struct{}{
		sid: {},
	}
	deny := map[string]struct{}{
		sid: {},
	}

	permitted, err := securityDescriptorAllowsCertificateEnrollment(
		descriptor,
		allow,
		deny,
	)
	if err != nil {
		t.Fatal(err)
	}
	if permitted {
		t.Fatal("explicit deny did not override enrollment allow")
	}
}

func TestSecurityDescriptorEnrollmentAllow(
	t *testing.T,
) {
	sid := "S-1-5-32-544"
	sidBytes := testSIDBytes(
		5,
		[]uint32{32, 544},
	)

	descriptor := testSecurityDescriptor(
		testSimpleACE(
			accessAllowedACE,
			adsRightDSControlAccess,
			sidBytes,
		),
	)

	permitted, err := securityDescriptorAllowsCertificateEnrollment(
		descriptor,
		map[string]struct{}{
			sid: {},
		},
		map[string]struct{}{
			sid: {},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !permitted {
		t.Fatal("enrollment allow was not recognized")
	}
}

func testSecurityDescriptor(
	aces ...[]byte,
) []byte {
	aclSize := 8
	for _, ace := range aces {
		aclSize += len(ace)
	}

	descriptor := make(
		[]byte,
		20+aclSize,
	)
	descriptor[0] = 1
	binary.LittleEndian.PutUint16(
		descriptor[2:4],
		0x8004,
	)
	binary.LittleEndian.PutUint32(
		descriptor[16:20],
		20,
	)

	acl := descriptor[20:]
	acl[0] = 2
	binary.LittleEndian.PutUint16(
		acl[2:4],
		uint16(aclSize),
	)
	binary.LittleEndian.PutUint16(
		acl[4:6],
		uint16(len(aces)),
	)

	offset := 8
	for _, ace := range aces {
		copy(
			acl[offset:],
			ace,
		)
		offset += len(ace)
	}

	return descriptor
}

func testSimpleACE(
	aceType byte,
	mask uint32,
	sid []byte,
) []byte {
	result := make(
		[]byte,
		8+len(sid),
	)
	result[0] = aceType
	binary.LittleEndian.PutUint16(
		result[2:4],
		uint16(len(result)),
	)
	binary.LittleEndian.PutUint32(
		result[4:8],
		mask,
	)
	copy(
		result[8:],
		sid,
	)
	return result
}

func testSIDBytes(
	identifierAuthority uint64,
	subAuthorities []uint32,
) []byte {
	result := make(
		[]byte,
		8+len(subAuthorities)*4,
	)
	result[0] = 1
	result[1] = byte(len(subAuthorities))

	for index := 0; index < 6; index++ {
		shift := uint((5 - index) * 8)
		result[2+index] = byte(
			identifierAuthority >> shift,
		)
	}

	offset := 8
	for _, subAuthority := range subAuthorities {
		binary.LittleEndian.PutUint32(
			result[offset:offset+4],
			subAuthority,
		)
		offset += 4
	}

	return result
}

func TestSecurityDescriptorDirectoryMemberWriteObjectSpecificAllow(
	t *testing.T,
) {
	sid := "S-1-5-32-544"
	sidBytes := testSIDBytes(5, []uint32{32, 544})
	ace := make([]byte, 12+16+len(sidBytes))
	ace[0] = accessAllowedObjectACE
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
	binary.LittleEndian.PutUint32(ace[4:8], adsRightDSWriteProp)
	binary.LittleEndian.PutUint32(ace[8:12], aceObjectTypePresent)
	copy(ace[12:28], activeDirectoryMemberAttributeGUID[:])
	copy(ace[28:], sidBytes)

	allowed, err := securityDescriptorAllowsDirectoryMemberWrite(
		testSecurityDescriptor(ace),
		map[string]struct{}{sid: {}},
		map[string]struct{}{sid: {}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("member attribute WriteProperty should be allowed")
	}
}

func TestDirectoryMemberWriteACEIgnoresDifferentObjectType(
	t *testing.T,
) {
	sidBytes := testSIDBytes(5, []uint32{32, 544})
	ace := make([]byte, 12+16+len(sidBytes))
	ace[0] = accessAllowedObjectACE
	binary.LittleEndian.PutUint16(ace[2:4], uint16(len(ace)))
	binary.LittleEndian.PutUint32(ace[4:8], adsRightDSWriteProp)
	binary.LittleEndian.PutUint32(ace[8:12], aceObjectTypePresent)
	for index := 12; index < 28; index++ {
		ace[index] = 0xAA
	}
	copy(ace[28:], sidBytes)

	applies, _, _, err := directoryMemberWriteACE(ace)
	if err != nil {
		t.Fatal(err)
	}
	if applies {
		t.Fatal("unrelated object-specific WriteProperty ACE applied to member attribute")
	}
}
