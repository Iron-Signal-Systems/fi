// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package freshinstall

import (
	"errors"
	"testing"
)

func protectedJournalParentFixture() JournalParentSecurity {
	return JournalParentSecurity{
		OwnerSID: journalSystemSID,
		DACLPresent: true,
		DACLProtected: true,
		Entries: []JournalParentACE{
			{SID: journalSystemSID, Type: journalAccessAllowedACE, Flags: journalParentInheritFlags, Mask: journalParentFullControl},
			{SID: journalAdministratorsSID, Type: journalAccessAllowedACE, Flags: journalParentInheritFlags, Mask: journalParentFullControl},
		},
	}
}

func TestJournalParentPolicyAcceptsOnlyExactProtectedPrivilegedACL(t *testing.T) {
	good := protectedJournalParentFixture()
	if err := ValidateJournalParentSecurity(good); err != nil {
		t.Fatalf("expected protected Windows parent DACL was rejected: %v", err)
	}
	good.OwnerSID = journalAdministratorsSID
	good.Entries[0], good.Entries[1] = good.Entries[1], good.Entries[0]
	if err := ValidateJournalParentSecurity(good); err != nil {
		t.Fatalf("approved owner and ACE order should not change authority: %v", err)
	}
}

func TestJournalParentPolicyRejectsAllBroadenedOrAmbiguousACLs(t *testing.T) {
	examples := []struct {
		name string
		change func(*JournalParentSecurity)
	}{
		{"untrusted owner", func(p *JournalParentSecurity) { p.OwnerSID = "S-1-5-21-100-200-300-500" }},
		{"missing owner", func(p *JournalParentSecurity) { p.OwnerSID = "" }},
		{"owner is trusted installer", func(p *JournalParentSecurity) { p.OwnerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" }},
		{"DACL not present", func(p *JournalParentSecurity) { p.DACLPresent = false }},
		{"DACL not protected", func(p *JournalParentSecurity) { p.DACLProtected = false }},
		{"defaulted DACL", func(p *JournalParentSecurity) { p.DACLDefaulted = true }},
		{"null DACL", func(p *JournalParentSecurity) { p.Entries = nil }},
		{"only SYSTEM entry", func(p *JournalParentSecurity) { p.Entries = p.Entries[:1] }},
		{"only admin entry", func(p *JournalParentSecurity) { p.Entries = p.Entries[1:] }},
		{"duplicate admin entry", func(p *JournalParentSecurity) { p.Entries[0] = p.Entries[1] }},
		{"extra Everyone entry", func(p *JournalParentSecurity) {
			p.Entries = append(p.Entries, JournalParentACE{
				SID: "S-1-1-0", Type: journalAccessAllowedACE, Flags: journalParentInheritFlags, Mask: journalParentFullControl,
			})
		}},
		{"Users instead of SYSTEM", func(p *JournalParentSecurity) { p.Entries[0].SID = "S-1-5-32-545" }},
		{"Authenticated Users instead of admins", func(p *JournalParentSecurity) { p.Entries[1].SID = "S-1-5-11" }},
		{"CREATOR OWNER", func(p *JournalParentSecurity) { p.Entries[0].SID = "S-1-3-0" }},
		{"deny ACE", func(p *JournalParentSecurity) { p.Entries[0].Type = 1 }},
		{"unknown/callback ACE", func(p *JournalParentSecurity) { p.Entries[0].Type = 9 }},
		{"inherited ACE", func(p *JournalParentSecurity) { p.Entries[0].Flags |= 0x10 }},
		{"inherit only ACE", func(p *JournalParentSecurity) { p.Entries[1].Flags |= 0x08 }},
		{"no propagate inheritance", func(p *JournalParentSecurity) { p.Entries[0].Flags |= 0x04 }},
		{"not inheritable to directory children", func(p *JournalParentSecurity) { p.Entries[0].Flags = 0x01 }},
		{"not inheritable to file children", func(p *JournalParentSecurity) { p.Entries[0].Flags = 0x02 }},
		{"not inheritable", func(p *JournalParentSecurity) { p.Entries[0].Flags = 0 }},
		{"missing standard delete right", func(p *JournalParentSecurity) { p.Entries[0].Mask &^= 0x00010000 }},
		{"missing append/create-subdirectory right", func(p *JournalParentSecurity) { p.Entries[0].Mask &^= 0x00000004 }},
		{"generic all right rather than normalized file mask", func(p *JournalParentSecurity) { p.Entries[0].Mask = 0x10000000 }},
		{"additional ACCESS_SYSTEM_SECURITY right", func(p *JournalParentSecurity) { p.Entries[1].Mask |= 0x01000000 }},
	}
	for _, tc := range examples {
		t.Run(tc.name, func(t *testing.T) {
			value := protectedJournalParentFixture()
			tc.change(&value)
			if err := ValidateJournalParentSecurity(value); !errors.Is(err, ErrUntrustedJournalParent) {
				t.Fatalf("unsafe journal parent accepted: %+v; error=%v", value, err)
			}
		})
	}
}
