// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import "testing"

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
