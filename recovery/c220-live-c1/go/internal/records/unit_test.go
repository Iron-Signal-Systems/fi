// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestValidateContentHashObservationPresent(t *testing.T) {
	value := ContentHashObservation{
		State:       ContentHashPresent,
		BytesHashed: "3",
		MD5:         "900150983cd24fb0d6963f7d28e17f72",
		SHA1:        "a9993e364706816aba3e25717850c26c9cd0d89d",
		SHA256:      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	}
	if err := ValidateContentHashObservation(value); err != nil {
		t.Fatal(err)
	}
}

func TestValidateContentHashObservationRejectsUppercase(t *testing.T) {
	value := ContentHashObservation{
		State:       ContentHashPresent,
		BytesHashed: "3",
		MD5:         "900150983CD24FB0D6963F7D28E17F72",
		SHA1:        "a9993e364706816aba3e25717850c26c9cd0d89d",
		SHA256:      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	}
	if err := ValidateContentHashObservation(value); err == nil {
		t.Fatal("uppercase MD5 accepted")
	}
}

func TestValidateContentHashObservationError(t *testing.T) {
	value := ContentHashObservation{State: ContentHashError, ReasonCode: "ContentOpenFailed", Detail: "access denied"}
	if err := ValidateContentHashObservation(value); err != nil {
		t.Fatal(err)
	}
}

func TestValidateDirectoryPrincipalSnapshot(t *testing.T) {
	sidRaw := testDomainSIDRaw(1106)
	guidRaw := []byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	disabled := false

	snapshot := DirectoryPrincipalSnapshot{
		ObservedAt:       "2026-08-22T11:00:00.000000000Z",
		CollectionMethod: DirectoryPrincipalCollectionMethod,
		DomainDNSName:    "iss.local",
		ServerDNSName:    "dc16.iss.local",
		NamingContext:    "DC=iss,DC=local",
		RequestedSIDs:    []string{"S-1-5-21-1-2-3-1106", "S-1-5-21-1-2-3-512"},
		Principals: []DirectoryPrincipalObservation{
			{
				SID:                    "S-1-5-21-1-2-3-1106",
				SIDRawBase64URL:        base64.RawURLEncoding.EncodeToString(sidRaw),
				ObjectGUID:             "12345678-9abc-def0-1122-334455667788",
				ObjectGUIDRawBase64URL: base64.RawURLEncoding.EncodeToString(guidRaw),
				DistinguishedName:      "CN=John,DC=iss,DC=local",
				SAMAccountName:         "jwood.admin",
				ObjectClasses:          []string{"top", "person", "organizationalPerson", "user"},
				UserAccountControlRaw:  "512",
				AccountDisabled:        &disabled,
				PrimaryGroupIDRaw:      "513",
			},
		},
		Memberships:  []DirectoryMembershipObservation{},
		NotFoundSIDs: []string{"S-1-5-21-1-2-3-512"},
	}

	if err := ValidateDirectoryPrincipalSnapshot(snapshot); err != nil {
		t.Fatalf("ValidateDirectoryPrincipalSnapshot: %v", err)
	}
}

func TestValidateDirectoryPrincipalSnapshotDirectMembershipSourceContract(t *testing.T) {
	disabled := false
	userGUID := []byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	groupGUID := []byte{0x79, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

	snapshot := DirectoryPrincipalSnapshot{
		ObservedAt:       "2026-08-22T11:00:00.000000000Z",
		CollectionMethod: DirectoryPrincipalCollectionMethod,
		DomainDNSName:    "iss.local",
		ServerDNSName:    "dc16.iss.local",
		NamingContext:    "DC=iss,DC=local",
		RequestedSIDs:    []string{"S-1-5-21-1-2-3-1106"},
		Principals: []DirectoryPrincipalObservation{
			{
				SID:                    "S-1-5-21-1-2-3-1106",
				SIDRawBase64URL:        base64.RawURLEncoding.EncodeToString(testDomainSIDRaw(1106)),
				ObjectGUID:             formatWindowsGUID(userGUID),
				ObjectGUIDRawBase64URL: base64.RawURLEncoding.EncodeToString(userGUID),
				DistinguishedName:      "CN=John,DC=iss,DC=local",
				SAMAccountName:         "jwood.admin",
				ObjectClasses:          []string{"top", "person", "organizationalPerson", "user"},
				UserAccountControlRaw:  "512",
				AccountDisabled:        &disabled,
				PrimaryGroupIDRaw:      "513",
			},
			{
				SID:                    "S-1-5-21-1-2-3-513",
				SIDRawBase64URL:        base64.RawURLEncoding.EncodeToString(testDomainSIDRaw(513)),
				ObjectGUID:             formatWindowsGUID(groupGUID),
				ObjectGUIDRawBase64URL: base64.RawURLEncoding.EncodeToString(groupGUID),
				DistinguishedName:      "CN=Domain Users,CN=Users,DC=iss,DC=local",
				SAMAccountName:         "Domain Users",
				ObjectClasses:          []string{"top", "group"},
			},
		},
		Memberships: []DirectoryMembershipObservation{
			{
				MemberSID: "S-1-5-21-1-2-3-1106",
				GroupSID:  "S-1-5-21-1-2-3-513",
				Source:    DirectoryMembershipSourceGroupMember,
			},
		},
		NotFoundSIDs: []string{},
	}

	if err := ValidateDirectoryPrincipalSnapshot(snapshot); err != nil {
		t.Fatalf("ValidateDirectoryPrincipalSnapshot: %v", err)
	}

	snapshot.Memberships[0].Source = DirectoryMembershipSource("PrimaryGroupID")
	if err := ValidateDirectoryPrincipalSnapshot(snapshot); err == nil {
		t.Fatal("PrimaryGroupID membership source accepted")
	}
}

func TestValidateDirectoryPrincipalSnapshotRejectsMembershipToUnknownGroup(t *testing.T) {
	disabled := false
	guidRaw := []byte{0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	snapshot := DirectoryPrincipalSnapshot{
		ObservedAt:       "2026-08-22T11:00:00.000000000Z",
		CollectionMethod: DirectoryPrincipalCollectionMethod,
		DomainDNSName:    "iss.local",
		ServerDNSName:    "dc16.iss.local",
		NamingContext:    "DC=iss,DC=local",
		RequestedSIDs:    []string{"S-1-5-21-1-2-3-1106"},
		Principals: []DirectoryPrincipalObservation{{
			SID:                    "S-1-5-21-1-2-3-1106",
			SIDRawBase64URL:        base64.RawURLEncoding.EncodeToString(testDomainSIDRaw(1106)),
			ObjectGUID:             formatWindowsGUID(guidRaw),
			ObjectGUIDRawBase64URL: base64.RawURLEncoding.EncodeToString(guidRaw),
			DistinguishedName:      "CN=John,DC=iss,DC=local",
			ObjectClasses:          []string{"top", "user"},
			UserAccountControlRaw:  "512",
			AccountDisabled:        &disabled,
		}},
		Memberships: []DirectoryMembershipObservation{{
			MemberSID: "S-1-5-21-1-2-3-1106",
			GroupSID:  "S-1-5-21-1-2-3-512",
			Source:    DirectoryMembershipSourceGroupMember,
		}},
		NotFoundSIDs: []string{},
	}

	if err := ValidateDirectoryPrincipalSnapshot(snapshot); err == nil {
		t.Fatal("expected membership to unknown group rejection")
	}
}

func TestValidateDirectoryPrincipalSnapshotRejectsGUIDMismatch(t *testing.T) {
	disabled := false
	sidRaw := []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}
	guidRaw := make([]byte, 16)
	snapshot := DirectoryPrincipalSnapshot{
		ObservedAt:       "2026-08-22T11:00:00.000000000Z",
		CollectionMethod: DirectoryPrincipalCollectionMethod,
		DomainDNSName:    "iss.local",
		ServerDNSName:    "dc16.iss.local",
		NamingContext:    "DC=iss,DC=local",
		RequestedSIDs:    []string{"S-1-5-18"},
		Principals: []DirectoryPrincipalObservation{{
			SID:                    "S-1-5-18",
			SIDRawBase64URL:        base64.RawURLEncoding.EncodeToString(sidRaw),
			ObjectGUID:             "11111111-1111-1111-1111-111111111111",
			ObjectGUIDRawBase64URL: base64.RawURLEncoding.EncodeToString(guidRaw),
			DistinguishedName:      "CN=System,DC=iss,DC=local",
			ObjectClasses:          []string{"top"},
			UserAccountControlRaw:  "512",
			AccountDisabled:        &disabled,
		}},
		Memberships:  []DirectoryMembershipObservation{},
		NotFoundSIDs: []string{},
	}

	if err := ValidateDirectoryPrincipalSnapshot(snapshot); err == nil {
		t.Fatal("expected GUID mismatch rejection")
	}
}

func testDomainSIDRaw(rid uint32) []byte {
	raw := []byte{
		1, 5, 0, 0, 0, 0, 0, 5,
		21, 0, 0, 0,
		1, 0, 0, 0,
		2, 0, 0, 0,
		3, 0, 0, 0,
		0, 0, 0, 0,
	}
	binary.LittleEndian.PutUint32(raw[len(raw)-4:], rid)
	return raw
}

func FuzzValidateReparseObservation(f *testing.F) {
	f.Add([]byte{}, uint32(0), "", "", "")
	f.Add(hardeningMountPointBuffer(`\??\C:\target`, `C:\target`), uint32(0xA0000003), hardeningUTF16Base64(`\??\C:\target`), hardeningUTF16Base64(`C:\target`), "")
	f.Add(hardeningSymlinkBuffer(`\??\C:\target`, `C:\target`, 0), uint32(0xA000000C), hardeningUTF16Base64(`\??\C:\target`), hardeningUTF16Base64(`C:\target`), "0x00000000")

	f.Fuzz(func(t *testing.T, raw []byte, tag uint32, substitute string, printName string, flags string) {
		format := ReparseDataFormatRaw
		switch tag {
		case 0xA0000003:
			format = ReparseDataFormatMountPoint
		case 0xA000000C:
			format = ReparseDataFormatSymbolicLink
		}
		observation := ReparseObservation{
			DataFormat:                     format,
			DataState:                      ReparseDataStatePresent,
			PrintNameUTF16LEBase64URL:      printName,
			RawBufferBase64URL:             base64.RawURLEncoding.EncodeToString(raw),
			State:                          ReparseStatePresent,
			SubstituteNameUTF16LEBase64URL: substitute,
			SymbolicLinkFlags:              flags,
			Tag:                            fmt.Sprintf("0x%08X", tag),
			TagName:                        ReparseTagName(fmt.Sprintf("0x%08X", tag)),
		}
		_ = ValidateReparseObservation(observation)
	})
}

func FuzzValidateStreamIdentity(f *testing.F) {
	f.Add([]byte{':', 0, ':', 0, '$', 0, 'D', 0, 'A', 0, 'T', 0, 'A', 0})
	f.Add([]byte{':', 0, 'x', 0, ':', 0, '$', 0, 'D', 0, 'A', 0, 'T', 0, 'A', 0})

	f.Fuzz(func(t *testing.T, raw []byte) {
		identity := StreamIdentity{
			Kind:                    StreamOther,
			NameUTF16LEBase64URL:    base64.RawURLEncoding.EncodeToString(raw),
			StreamType:              "Unknown",
			RawNameUTF16LEBase64URL: base64.RawURLEncoding.EncodeToString(raw),
		}
		_ = ValidateStreamIdentity(identity)
	})
}

func TestValidateReparseObservationRejectsMountPointParsedFieldMismatch(t *testing.T) {
	raw := hardeningMountPointBuffer(`\??\C:\Actual`, `C:\Actual`)
	observation := ReparseObservation{
		DataFormat:                     ReparseDataFormatMountPoint,
		DataState:                      ReparseDataStatePresent,
		PrintNameUTF16LEBase64URL:      hardeningUTF16Base64(`C:\SomethingElse`),
		RawBufferBase64URL:             base64.RawURLEncoding.EncodeToString(raw),
		State:                          ReparseStatePresent,
		SubstituteNameUTF16LEBase64URL: hardeningUTF16Base64(`\??\C:\Actual`),
		Tag:                            "0xA0000003",
		TagName:                        "IO_REPARSE_TAG_MOUNT_POINT",
	}
	if err := ValidateReparseObservation(observation); err == nil || !strings.Contains(err.Error(), "print_name") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateReparseObservationRejectsSymlinkFlagsMismatch(t *testing.T) {
	raw := hardeningSymlinkBuffer(`\??\C:\Actual`, `C:\Actual`, 0)
	observation := ReparseObservation{
		DataFormat:                     ReparseDataFormatSymbolicLink,
		DataState:                      ReparseDataStatePresent,
		PrintNameUTF16LEBase64URL:      hardeningUTF16Base64(`C:\Actual`),
		RawBufferBase64URL:             base64.RawURLEncoding.EncodeToString(raw),
		State:                          ReparseStatePresent,
		SubstituteNameUTF16LEBase64URL: hardeningUTF16Base64(`\??\C:\Actual`),
		SymbolicLinkFlags:              "0x00000001",
		Tag:                            "0xA000000C",
		TagName:                        "IO_REPARSE_TAG_SYMLINK",
	}
	if err := ValidateReparseObservation(observation); err == nil || !strings.Contains(err.Error(), "symbolic_link_flags") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateStreamIdentityRejectsInterpretationMismatch(t *testing.T) {
	identity := StreamIdentityFromRawUTF16(hardeningUTF16(`:secret:$DATA`))
	identity.NameUTF16LEBase64URL = hardeningUTF16Base64("innocent")
	if err := ValidateStreamIdentity(identity); err == nil || !strings.Contains(err.Error(), "Conflict") {
		t.Fatalf("error = %v", err)
	}
}

func TestValidateNTFSObjectIdentityBounds(t *testing.T) {
	valid := NTFSObjectIdentity{
		MethodVersion:       "windows-file-id-info-ntfs/0.1",
		FileReferenceNumber: "281474976710655",
		SequenceNumber:      "65535",
	}
	if err := ValidateNTFSObjectIdentity(valid); err != nil {
		t.Fatal(err)
	}
	valid.FileReferenceNumber = "281474976710656"
	if err := ValidateNTFSObjectIdentity(valid); err == nil || !strings.Contains(err.Error(), "OutOfRange") {
		t.Fatalf("file reference error = %v", err)
	}
	valid.FileReferenceNumber = "1"
	valid.SequenceNumber = "65536"
	if err := ValidateNTFSObjectIdentity(valid); err == nil || !strings.Contains(err.Error(), "OutOfRange") {
		t.Fatalf("sequence error = %v", err)
	}
}

func TestValidateVolumeIdentityGUIDShape(t *testing.T) {
	identity := VolumeIdentity{
		MethodVersion: "windows-file-id-info-ntfs/0.1",
		VolumeGUID:    `\\?\Volume{11111111-2222-3333-4444-555555555555}\`,
		VolumeSerial:  "1",
	}
	if err := ValidateVolumeIdentity(identity); err != nil {
		t.Fatal(err)
	}
	identity.VolumeGUID = `C:\`
	if err := ValidateVolumeIdentity(identity); err == nil || !strings.Contains(err.Error(), "InvalidVolumeGUID") {
		t.Fatalf("error = %v", err)
	}
}

func hardeningMountPointBuffer(substitute string, printName string) []byte {
	substituteBytes := hardeningUTF16Bytes(hardeningUTF16(substitute))
	printBytes := hardeningUTF16Bytes(hardeningUTF16(printName))
	pathBytes := append(append([]byte(nil), substituteBytes...), printBytes...)
	dataLength := 8 + len(pathBytes)
	raw := make([]byte, 8+dataLength)
	binary.LittleEndian.PutUint32(raw[0:4], 0xA0000003)
	binary.LittleEndian.PutUint16(raw[4:6], uint16(dataLength))
	binary.LittleEndian.PutUint16(raw[8:10], 0)
	binary.LittleEndian.PutUint16(raw[10:12], uint16(len(substituteBytes)))
	binary.LittleEndian.PutUint16(raw[12:14], uint16(len(substituteBytes)))
	binary.LittleEndian.PutUint16(raw[14:16], uint16(len(printBytes)))
	copy(raw[16:], pathBytes)
	return raw
}

func hardeningSymlinkBuffer(substitute string, printName string, flags uint32) []byte {
	substituteBytes := hardeningUTF16Bytes(hardeningUTF16(substitute))
	printBytes := hardeningUTF16Bytes(hardeningUTF16(printName))
	pathBytes := append(append([]byte(nil), substituteBytes...), printBytes...)
	dataLength := 12 + len(pathBytes)
	raw := make([]byte, 8+dataLength)
	binary.LittleEndian.PutUint32(raw[0:4], 0xA000000C)
	binary.LittleEndian.PutUint16(raw[4:6], uint16(dataLength))
	binary.LittleEndian.PutUint16(raw[8:10], 0)
	binary.LittleEndian.PutUint16(raw[10:12], uint16(len(substituteBytes)))
	binary.LittleEndian.PutUint16(raw[12:14], uint16(len(substituteBytes)))
	binary.LittleEndian.PutUint16(raw[14:16], uint16(len(printBytes)))
	binary.LittleEndian.PutUint32(raw[16:20], flags)
	copy(raw[20:], pathBytes)
	return raw
}

func hardeningUTF16(value string) []uint16 {
	units := make([]uint16, len(value))
	for index := range value {
		units[index] = uint16(value[index])
	}
	return units
}

func hardeningUTF16Bytes(units []uint16) []byte {
	encoded := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(encoded[index*2:], unit)
	}
	return encoded
}

func hardeningUTF16Base64(value string) string {
	return base64.RawURLEncoding.EncodeToString(hardeningUTF16Bytes(hardeningUTF16(value)))
}

func TestValidateLocalPrincipalSnapshot(t *testing.T) {
	disabled := uint32(0x0002)
	_ = disabled
	snapshot := LocalPrincipalSnapshot{
		ObservedAt:       "2026-08-22T12:00:00.000000000Z",
		CollectionMethod: LocalPrincipalCollectionMethod,
		ComputerName:     "SERVER1",
		Users: []LocalUserObservation{{
			SID: "S-1-5-21-1-2-3-1001", SIDRawBase64URL: "AQUAAAAAAAUVAAAAAQAAAAIAAAADAAAA6QMAAA",
			NameDisplay: "user1", NameUTF16LEBase64URL: "dQBzAGUAcgAxAA", FlagsRaw: "512",
		}},
		Groups: []LocalGroupObservation{{
			SID: "S-1-5-32-544", SIDRawBase64URL: "AQIAAAAAAAUgAAAAIAIAAA",
			AccountDomain: "BUILTIN", NameDisplay: "Administrators", NameUTF16LEBase64URL: "QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzAA",
			MembershipState: LocalMembershipComplete,
		}},
		Memberships: []LocalGroupMembershipObservation{{
			GroupSID: "S-1-5-32-544", MemberSID: "S-1-5-21-1-2-3-1001",
			MemberSIDRawBase64URL:      "AQUAAAAAAAUVAAAAAQAAAAIAAAADAAAA6QMAAA",
			MemberDomainAndNameDisplay: "SERVER1\\user1", SIDNameUseRaw: "1", SIDNameUseName: "User",
		}},
	}
	if err := ValidateLocalPrincipalSnapshot(snapshot); err != nil {
		t.Fatalf("ValidateLocalPrincipalSnapshot: %v", err)
	}
}

func TestValidateLocalPrincipalSnapshotRejectsUnknownMembershipState(t *testing.T) {
	snapshot := LocalPrincipalSnapshot{
		ObservedAt:       "2026-08-22T12:00:00.000000000Z",
		CollectionMethod: LocalPrincipalCollectionMethod,
		ComputerName:     "SERVER1",
		Groups: []LocalGroupObservation{{
			SID: "S-1-5-32-544", SIDRawBase64URL: "AQIAAAAAAAUgAAAAIAIAAA",
			NameDisplay: "Administrators", NameUTF16LEBase64URL: "QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzAA",
			MembershipState: "Unknown",
		}},
	}
	if err := ValidateLocalPrincipalSnapshot(snapshot); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateOperationRecordComplete(t *testing.T) {
	value := validOperationRecordForTest()
	if err := ValidateOperationRecord(value); err != nil {
		t.Fatal(err)
	}
}

func TestValidateOperationRecordConfiguredKinds(t *testing.T) {
	for _, kind := range []OperationKind{
		OperationBaseline,
		OperationReconciliation,
		OperationSupportingSourceRefresh,
		OperationUSNCatchUp,
		OperationWindowsSecurityCatchUp,
	} {
		value := validOperationRecordForTest()
		value.Kind = kind
		if err := ValidateOperationRecord(value); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
}

func TestValidateOperationRecordPartialRequiresReason(t *testing.T) {
	value := validOperationRecordForTest()
	value.Outcome = OperationPartial
	if err := ValidateOperationRecord(value); err == nil {
		t.Fatal("expected missing reason_code to be rejected")
	}
}

func TestValidateOperationRecordRejectsBackwardTime(t *testing.T) {
	value := validOperationRecordForTest()
	value.StartedAt = "2026-08-22T17:00:02.000000000Z"
	value.FinishedAt = "2026-08-22T17:00:01.000000000Z"
	if err := ValidateOperationRecord(value); err == nil {
		t.Fatal("expected backward operation time to be rejected")
	}
}

func TestValidateOperationRecordRejectsUnknownKind(t *testing.T) {
	value := validOperationRecordForTest()
	value.Kind = OperationKind("Magic")
	if err := ValidateOperationRecord(value); err == nil {
		t.Fatal("expected unknown operation kind to be rejected")
	}
}

func validOperationRecordForTest() OperationRecord {
	return OperationRecord{
		OperationID: "op-0123456789abcdef0123456789abcdef",
		ScopeID:     "manual-test",
		Kind:        OperationUSNRead,
		StartedAt:   "2026-08-22T17:00:00.000000000Z",
		FinishedAt:  "2026-08-22T17:00:01.000000000Z",
		Outcome:     OperationComplete,
	}
}

func TestValidateParentObjectBindingPresent(t *testing.T) {
	binding := ParentObjectBindingFor(NTFSObjectIdentity{
		MethodVersion:       "windows-file-id-info-ntfs/0.1",
		FileReferenceNumber: "42",
		SequenceNumber:      "7",
	})
	if err := ValidateParentObjectBinding(binding); err != nil {
		t.Fatal(err)
	}
}

func TestValidateParentObjectBindingGovernedRootRejectsIdentity(t *testing.T) {
	identity := NTFSObjectIdentity{
		MethodVersion:       "windows-file-id-info-ntfs/0.1",
		FileReferenceNumber: "42",
		SequenceNumber:      "7",
	}
	binding := ParentObjectBinding{
		State:          ParentBindingGovernedRoot,
		ObjectIdentity: &identity,
	}
	if err := ValidateParentObjectBinding(binding); err == nil {
		t.Fatal("expected governed-root parent binding to reject object identity")
	}
}

func TestValidateParentObjectBindingErrorRequiresReason(t *testing.T) {
	binding := ParentObjectBinding{State: ParentBindingError}
	if err := ValidateParentObjectBinding(binding); err == nil {
		t.Fatal("expected error parent binding to require reason code")
	}
}

func TestValidateProcessIdentityObservation(t *testing.T) {
	observation := ProcessIdentityObservation{
		ObservedAt:       "2026-08-22T09:00:00.000000000Z",
		CollectionMethod: ProcessIdentityCollectionMethod,
		Computer:         ComputerIdentity{NetBIOSName: "ISS-FS-01"},
		Token: ProcessTokenObservation{
			User:              TokenPrincipalObservation{SID: "S-1-5-18"},
			TokenTypeRaw:      "1",
			TokenTypeName:     "Primary",
			ElevationTypeRaw:  "1",
			ElevationTypeName: "Default",
			Groups: []TokenGroupObservation{{
				Index:         "0",
				Principal:     TokenPrincipalObservation{SID: "S-1-5-32-544"},
				AttributesRaw: "7",
			}},
			Privileges: []TokenPrivilegeObservation{{
				Index:         "0",
				LUIDLow:       "20",
				LUIDHigh:      "0",
				AttributesRaw: "3",
			}},
		},
	}
	if err := ValidateProcessIdentityObservation(observation); err != nil {
		t.Fatal(err)
	}
}

func TestValidateProcessIdentityObservationRejectsBadGroupIndex(t *testing.T) {
	observation := ProcessIdentityObservation{
		ObservedAt:       "2026-08-22T09:00:00.000000000Z",
		CollectionMethod: ProcessIdentityCollectionMethod,
		Computer:         ComputerIdentity{NetBIOSName: "ISS-FS-01"},
		Token: ProcessTokenObservation{
			User:              TokenPrincipalObservation{SID: "S-1-5-18"},
			TokenTypeRaw:      "1",
			TokenTypeName:     "Primary",
			ElevationTypeRaw:  "1",
			ElevationTypeName: "Default",
			Groups: []TokenGroupObservation{{
				Index:         "9",
				Principal:     TokenPrincipalObservation{SID: "S-1-5-32-544"},
				AttributesRaw: "7",
			}},
		},
	}
	if err := ValidateProcessIdentityObservation(observation); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestReparseTagNameKnownValues(t *testing.T) {
	tests := []struct {
		tag  string
		name string
	}{
		{"0x00000000", "IO_REPARSE_TAG_RESERVED_ZERO"},
		{"0x00000001", "IO_REPARSE_TAG_RESERVED_ONE"},
		{"0x00000002", "IO_REPARSE_TAG_RESERVED_TWO"},
		{"0x80000005", "IO_REPARSE_TAG_DRIVE_EXTENDER"},
		{"0x80000006", "IO_REPARSE_TAG_HSM2"},
		{"0x80000007", "IO_REPARSE_TAG_SIS"},
		{"0x80000008", "IO_REPARSE_TAG_WIM"},
		{"0x80000009", "IO_REPARSE_TAG_CSV"},
		{"0x8000000A", "IO_REPARSE_TAG_DFS"},
		{"0x8000000B", "IO_REPARSE_TAG_FILTER_MANAGER"},
		{"0x80000012", "IO_REPARSE_TAG_DFSR"},
		{"0x80000013", "IO_REPARSE_TAG_DEDUP"},
		{"0x80000014", "IO_REPARSE_TAG_NFS"},
		{"0x80000015", "IO_REPARSE_TAG_FILE_PLACEHOLDER"},
		{"0x80000016", "IO_REPARSE_TAG_DFM"},
		{"0x80000017", "IO_REPARSE_TAG_WOF"},
		{"0x80000018", "IO_REPARSE_TAG_WCI"},
		{"0x8000001B", "IO_REPARSE_TAG_APPEXECLINK"},
		{"0x8000001E", "IO_REPARSE_TAG_STORAGE_SYNC"},
		{"0x80000020", "IO_REPARSE_TAG_UNHANDLED"},
		{"0x80000021", "IO_REPARSE_TAG_ONEDRIVE"},
		{"0x80000023", "IO_REPARSE_TAG_AF_UNIX"},
		{"0x80000024", "IO_REPARSE_TAG_LX_FIFO"},
		{"0x80000025", "IO_REPARSE_TAG_LX_CHR"},
		{"0x80000026", "IO_REPARSE_TAG_LX_BLK"},
		{"0x9000001A", "IO_REPARSE_TAG_CLOUD"},
		{"0x9000001C", "IO_REPARSE_TAG_PROJFS"},
		{"0x90000027", "IO_REPARSE_TAG_STORAGE_SYNC_FOLDER"},
		{"0x90001018", "IO_REPARSE_TAG_WCI_1"},
		{"0x9000101A", "IO_REPARSE_TAG_CLOUD_1"},
		{"0x9000201A", "IO_REPARSE_TAG_CLOUD_2"},
		{"0x9000301A", "IO_REPARSE_TAG_CLOUD_3"},
		{"0x9000401A", "IO_REPARSE_TAG_CLOUD_4"},
		{"0x9000501A", "IO_REPARSE_TAG_CLOUD_5"},
		{"0x9000601A", "IO_REPARSE_TAG_CLOUD_6"},
		{"0x9000701A", "IO_REPARSE_TAG_CLOUD_7"},
		{"0x9000801A", "IO_REPARSE_TAG_CLOUD_8"},
		{"0x9000901A", "IO_REPARSE_TAG_CLOUD_9"},
		{"0x9000A01A", "IO_REPARSE_TAG_CLOUD_A"},
		{"0x9000B01A", "IO_REPARSE_TAG_CLOUD_B"},
		{"0x9000C01A", "IO_REPARSE_TAG_CLOUD_C"},
		{"0x9000D01A", "IO_REPARSE_TAG_CLOUD_D"},
		{"0x9000E01A", "IO_REPARSE_TAG_CLOUD_E"},
		{"0x9000F01A", "IO_REPARSE_TAG_CLOUD_F"},
		{"0xA0000003", "IO_REPARSE_TAG_MOUNT_POINT"},
		{"0xA000000C", "IO_REPARSE_TAG_SYMLINK"},
		{"0xA0000010", "IO_REPARSE_TAG_IIS_CACHE"},
		{"0xA0000019", "IO_REPARSE_TAG_GLOBAL_REPARSE"},
		{"0xA000001D", "IO_REPARSE_TAG_LX_SYMLINK"},
		{"0xA000001F", "IO_REPARSE_TAG_WCI_TOMBSTONE"},
		{"0xA0000022", "IO_REPARSE_TAG_PROJFS_TOMBSTONE"},
		{"0xA0000027", "IO_REPARSE_TAG_WCI_LINK"},
		{"0xA0001027", "IO_REPARSE_TAG_WCI_LINK_1"},
		{"0xC0000004", "IO_REPARSE_TAG_HSM"},
		{"0xC0000014", "IO_REPARSE_TAG_APPXSTRM"},
	}

	for _, test := range tests {
		if got := ReparseTagName(test.tag); got != test.name {
			t.Fatalf("ReparseTagName(%s) = %q, want %q", test.tag, got, test.name)
		}
	}
}

func TestReparseTagNameUnknown(t *testing.T) {
	if got := ReparseTagName("0xDEADBEEF"); got != ReparseTagNameNotKnown {
		t.Fatalf("unknown tag name = %q", got)
	}
}

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

func TestValidateUSNContinuityGapObservation(t *testing.T) {
	value := USNContinuityGapObservation{
		ObservedAt:            "2026-08-26T12:00:00.000000000Z",
		CollectionMethod:      WindowsUSNCollectionMethod,
		ScopeID:               "root-a",
		GovernedRoot:          `C:\Data`,
		ReasonCode:            "JournalIDChanged",
		CheckpointJournalID:   "100",
		CheckpointNextUSN:     "200",
		CurrentJournalID:      "101",
		CurrentFirstUSN:       "300",
		CurrentLowestValidUSN: "300",
		CurrentNextUSN:        "400",
		CoverageState:         USNContinuityGapCoverageIncomplete,
		ReconciliationAction:  USNContinuityGapReconcileBaselineAndCatchUp,
	}
	if err := ValidateUSNContinuityGapObservation(value); err != nil {
		t.Fatal(err)
	}

	value.ReasonCode = ""
	if err := ValidateUSNContinuityGapObservation(value); err == nil {
		t.Fatal("missing reason code was accepted")
	}
}

func testUSNVolumeIdentity() VolumeIdentity {
	return VolumeIdentity{
		MethodVersion: "windows-file-id-info-ntfs/0.1",
		VolumeGUID:    `\\?\Volume{11111111-1111-1111-1111-111111111111}\`,
		VolumeSerial:  "123",
	}
}

func testUSNObjectIdentity(record, sequence string) NTFSObjectIdentity {
	return NTFSObjectIdentity{
		MethodVersion:       "windows-file-id-info-ntfs/0.1",
		FileReferenceNumber: record,
		SequenceNumber:      sequence,
	}
}

func TestValidateUSNJournalState(t *testing.T) {
	state := USNJournalState{
		ObservedAt:       "2026-08-22T13:00:00.000000000Z",
		CollectionMethod: "WindowsNTFSUSNJournalV0",
		ScopeID:          "scope-test",
		VolumeIdentity:   testUSNVolumeIdentity(),
		JournalID:        "10",
		FirstUSN:         "20",
		NextUSN:          "30",
		LowestValidUSN:   "20",
		MaxUSN:           "100",
		MaximumSize:      "1048576",
		AllocationDelta:  "65536",
	}
	if err := ValidateUSNJournalState(state); err != nil {
		t.Fatal(err)
	}
}

func TestValidateUSNReadBatch(t *testing.T) {
	batch := USNReadBatch{
		ObservedAt:       "2026-08-22T13:00:00.000000000Z",
		CollectionMethod: "WindowsNTFSUSNJournalV0",
		ScopeID:          "scope-test",
		VolumeIdentity:   testUSNVolumeIdentity(),
		JournalID:        "10",
		StartUSN:         "20",
		NextUSN:          "31",
		Records: []USNChangeObservation{{
			MajorVersion:             "2",
			MinorVersion:             "0",
			FileIdentity:             testUSNObjectIdentity("100", "2"),
			ParentIdentity:           testUSNObjectIdentity("50", "3"),
			USN:                      "30",
			Timestamp:                "2026-08-22T13:00:00.000000000Z",
			ReasonRaw:                "256",
			ReasonNames:              []string{"FileCreate"},
			SourceInfoRaw:            "0",
			SecurityID:               "7",
			FileAttributesRaw:        "32",
			FileNameUTF16LEBase64URL: "ZgBpAGwAZQAuAHQAeAB0AA",
		}},
	}
	if err := ValidateUSNReadBatch(batch); err != nil {
		t.Fatal(err)
	}
}

func TestValidateUSNReadBatchRejectsDescendingUSN(t *testing.T) {
	base := USNChangeObservation{
		MajorVersion:             "2",
		MinorVersion:             "0",
		FileIdentity:             testUSNObjectIdentity("100", "2"),
		ParentIdentity:           testUSNObjectIdentity("50", "3"),
		Timestamp:                "2026-08-22T13:00:00.000000000Z",
		ReasonRaw:                "256",
		ReasonNames:              []string{"FileCreate"},
		SourceInfoRaw:            "0",
		SecurityID:               "7",
		FileAttributesRaw:        "32",
		FileNameUTF16LEBase64URL: "ZgBpAGwAZQAuAHQAeAB0AA",
	}
	first := base
	first.USN = "31"
	second := base
	second.USN = "30"

	batch := USNReadBatch{
		ObservedAt:       "2026-08-22T13:00:00.000000000Z",
		CollectionMethod: "WindowsNTFSUSNJournalV0",
		ScopeID:          "scope-test",
		VolumeIdentity:   testUSNVolumeIdentity(),
		JournalID:        "10",
		StartUSN:         "20",
		NextUSN:          "32",
		Records:          []USNChangeObservation{first, second},
	}
	if err := ValidateUSNReadBatch(batch); err == nil {
		t.Fatal("expected descending USN validation failure")
	}
}

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

func TestValidateWindowsSecurityContinuityGapObservation(t *testing.T) {
	value := WindowsSecurityContinuityGapObservation{
		ObservedAt:                 "2026-08-26T12:00:00.123456700Z",
		CollectionMethod:           WindowsSecurityCollectionMethod,
		Channel:                    "Security",
		ScopeID:                    "windows-security-local",
		ReasonCode:                 "SecurityLogRecordsOverwritten",
		CheckpointEventRecordID:    "100",
		CurrentOldestEventRecordID: "200",
		CurrentNewestEventRecordID: "300",
		CoverageState:              WindowsSecurityContinuityGapCoverageIncomplete,
		ReconciliationAction:       WindowsSecurityContinuityGapReconcileCurrentStateBaseline,
	}
	if err := ValidateWindowsSecurityContinuityGapObservation(value); err != nil {
		t.Fatal(err)
	}
}

func TestValidateWindowsSecurityContinuityGapObservationRejectsUnknownReason(t *testing.T) {
	value := WindowsSecurityContinuityGapObservation{
		ObservedAt:                 "2026-08-26T12:00:00.123456700Z",
		CollectionMethod:           WindowsSecurityCollectionMethod,
		Channel:                    "Security",
		ScopeID:                    "windows-security-local",
		ReasonCode:                 "NotARealGap",
		CheckpointEventRecordID:    "100",
		CurrentOldestEventRecordID: "200",
		CurrentNewestEventRecordID: "300",
		CoverageState:              WindowsSecurityContinuityGapCoverageIncomplete,
		ReconciliationAction:       WindowsSecurityContinuityGapReconcileCurrentStateBaseline,
	}
	if err := ValidateWindowsSecurityContinuityGapObservation(value); err == nil {
		t.Fatal("unknown reason was accepted")
	}
}

func TestValidateWindowsSecurityEventObservation(t *testing.T) {
	value := WindowsSecurityEventObservation{
		ObservedAt:       "2026-08-24T10:00:00.000000000Z",
		CollectionMethod: WindowsSecurityCollectionMethod,
		Channel:          "Security",
		Provider:         "Microsoft-Windows-Security-Auditing",
		EventID:          "4656",
		EventRecordID:    "123",
		TimeCreated:      "2026-08-24T10:00:00.000000000Z",
		Computer:         "ISS-FS-01.iss.local",
		AuditResult:      WindowsSecurityAuditFailure,
		ScopeBasis:       WindowsSecurityScopePathMatched,
		MatchedScopes:    []WindowsSecurityMatchedScope{{ScopeID: "root-a", GovernedRoot: `C:\Data`}},
		Fields:           []WindowsSecurityEventField{},
		RawXML:           "<Event/>",
	}
	if err := ValidateWindowsSecurityEventObservation(value); err != nil {
		t.Fatal(err)
	}
}

func TestValidateWindowsSecurityEventObservationAllowsSharePathMatch(t *testing.T) {
	value := WindowsSecurityEventObservation{
		ObservedAt:         "2026-08-25T22:00:00.000000000Z",
		CollectionMethod:   WindowsSecurityCollectionMethod,
		Channel:            "Security",
		Provider:           "Microsoft-Windows-Security-Auditing",
		EventID:            "5145",
		EventRecordID:      "29486",
		TimeCreated:        "2026-08-25T22:00:00.000000000Z",
		Computer:           "AdminBox.iss.local",
		AuditResult:        WindowsSecurityAuditSuccess,
		ScopeBasis:         WindowsSecurityScopeSharePathMatched,
		MatchedScopes:      []WindowsSecurityMatchedScope{{ScopeID: "root-a", GovernedRoot: `C:\Users\jwood.admin\Downloads`}},
		Fields:             []WindowsSecurityEventField{},
		SourceIP:           "192.168.1.210",
		ShareName:          `\\*\FI-Downloads`,
		ShareLocalPath:     `\??\C:\Users\jwood.admin\Downloads`,
		RelativeTargetName: "fi-smb-remote-denied.txt",
		RawXML:             "<Event/>",
	}
	if err := ValidateWindowsSecurityEventObservation(value); err != nil {
		t.Fatal(err)
	}
}

func TestValidateWindowsSecurityCoverageObservation(t *testing.T) {
	value := WindowsSecurityCoverageObservation{
		ObservedAt:          "2026-08-25T09:00:00.000000000Z",
		CollectionMethod:    WindowsSecurityCollectionMethod,
		SecurityLogReadable: true,
		FileSystemPolicy: WindowsSecurityAuditPolicyObservation{
			SubcategoryGUID:     "{0CCE921D-69AE-11D9-BED3-505054503030}",
			AuditingInformation: "3",
			SuccessEnabled:      true,
			FailureEnabled:      true,
		},
		HandleManipulationPolicy: WindowsSecurityAuditPolicyObservation{
			SubcategoryGUID:     "{0CCE9223-69AE-11D9-BED3-505054503030}",
			AuditingInformation: "2",
			FailureEnabled:      true,
		},
		DetailedFileSharePolicy: WindowsSecurityAuditPolicyObservation{
			SubcategoryGUID:     "{0CCE9244-69AE-11D9-BED3-505054503030}",
			AuditingInformation: "3",
			SuccessEnabled:      true,
			FailureEnabled:      true,
		},
		AuditPolicyChangePolicy: WindowsSecurityAuditPolicyObservation{
			SubcategoryGUID:     "{0CCE922F-69AE-11D9-BED3-505054503030}",
			AuditingInformation: "1",
			SuccessEnabled:      true,
		},
		Roots:  []WindowsSecurityRootAuditCoverage{},
		Status: WindowsSecurityCoverageReady,
	}

	if err := ValidateWindowsSecurityCoverageObservation(value); err != nil {
		t.Fatal(err)
	}

	value.DetailedFileSharePolicy = WindowsSecurityAuditPolicyObservation{}

	if err := ValidateWindowsSecurityCoverageObservation(value); err == nil {
		t.Fatal("missing Detailed File Share policy was accepted")
	}
}
