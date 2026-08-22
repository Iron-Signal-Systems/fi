// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"encoding/base64"
	"encoding/binary"
	"testing"
)

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

func TestValidateDirectoryPrincipalSnapshotAllowsDiscoveredGroupAndDirectMembership(t *testing.T) {
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
				Source:    DirectoryMembershipSourcePrimaryGroupID,
			},
		},
		NotFoundSIDs: []string{},
	}

	if err := ValidateDirectoryPrincipalSnapshot(snapshot); err != nil {
		t.Fatalf("ValidateDirectoryPrincipalSnapshot: %v", err)
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
