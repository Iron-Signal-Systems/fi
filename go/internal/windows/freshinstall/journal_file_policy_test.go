// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package freshinstall

import (
	"errors"
	"testing"
)

func canonicalJournalFileSecurity() JournalParentSecurity {
	return JournalParentSecurity{
		OwnerSID: journalSystemSID,
		DACLPresent: true,
		Entries: []JournalParentACE{
			{SID: journalSystemSID, Type: journalAccessAllowedACE,
				Flags: journalFileInheritedACE, Mask: journalParentFullControl},
			{SID: journalAdministratorsSID, Type: journalAccessAllowedACE,
				Flags: journalFileInheritedACE, Mask: journalParentFullControl},
		},
	}
}

func TestCreationJournalFileRequiresTwoPrivilegedInheritedACEs(t *testing.T) {
	valid := canonicalJournalFileSecurity()
	if err := ValidateCreationJournalFileSecurity(valid); err != nil {
		t.Fatalf("canonical file security refused: %v", err)
	}
	valid.OwnerSID = journalAdministratorsSID
	valid.Entries[0].Flags = journalFileInheritedACE | journalParentInheritFlags
	if err := ValidateCreationJournalFileSecurity(valid); err != nil {
		t.Fatalf("inherited OI/CI form refused: %v", err)
	}
}

func TestCreationJournalFileRejectsPrivilegeWideningAndForgedInheritance(t *testing.T) {
	tests := []struct {
		name string
		edit func(*JournalParentSecurity)
	}{
		{"untrusted owner", func(v *JournalParentSecurity) { v.OwnerSID = "S-1-5-11" }},
		{"defaulted owner", func(v *JournalParentSecurity) { v.OwnerDefaulted = true }},
		{"missing DACL", func(v *JournalParentSecurity) { v.DACLPresent = false }},
		{"defaulted DACL", func(v *JournalParentSecurity) { v.DACLDefaulted = true }},
		{"no ACE", func(v *JournalParentSecurity) { v.Entries = nil }},
		{"missing administrator", func(v *JournalParentSecurity) { v.Entries = v.Entries[:1] }},
		{"extra ACE", func(v *JournalParentSecurity) {
			v.Entries = append(v.Entries, JournalParentACE{
				SID: "S-1-1-0", Type: journalAccessAllowedACE,
				Flags: journalFileInheritedACE, Mask: journalParentFullControl,
			})
		}},
		{"duplicate SYSTEM", func(v *JournalParentSecurity) { v.Entries[1].SID = journalSystemSID }},
		{"explicit rather than inherited", func(v *JournalParentSecurity) { v.Entries[0].Flags = 0 }},
		{"inherit only", func(v *JournalParentSecurity) { v.Entries[0].Flags = 0x18 }},
		{"unexpected ACE flag", func(v *JournalParentSecurity) { v.Entries[0].Flags = 0x14 }},
		{"write without full control", func(v *JournalParentSecurity) { v.Entries[0].Mask = 0x0012019f }},
		{"unexpanded generic rights", func(v *JournalParentSecurity) { v.Entries[0].Mask = 0x10000000 }},
		{"deny ACE", func(v *JournalParentSecurity) { v.Entries[0].Type = 1 }},
		{"unexpected trustee", func(v *JournalParentSecurity) { v.Entries[1].SID = "S-1-5-11" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			value := canonicalJournalFileSecurity()
			tc.edit(&value)
			if err := ValidateCreationJournalFileSecurity(value); !errors.Is(err, ErrUntrustedJournalFile) {
				t.Fatalf("untrusted file ACE/owner accepted: %+v, err=%v", value, err)
			}
		})
	}
}
