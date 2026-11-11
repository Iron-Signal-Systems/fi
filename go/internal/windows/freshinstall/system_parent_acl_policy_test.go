// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package freshinstall

import (
	"errors"
	"testing"
)

func safeSystemParentACL() SystemParentACL {
	return SystemParentACL{
		OwnerSID: journalAdministratorsSID,
		DACLPresent: true,
		Entries: []SystemParentACE{
			{SID: journalSystemSID, Type: systemParentAllowACE, Mask: journalParentFullControl, Flags: 0x13},
			{SID: journalAdministratorsSID, Type: systemParentAllowACE, Mask: journalParentFullControl, Flags: 0x03},
			{SID: "S-1-5-32-545", Type: systemParentAllowACE, Mask: systemParentBenignReadMask, Flags: 0x10},
		},
	}
}

func TestSystemParentACLAcceptsBoundedInheritedReadOnlyAccess(t *testing.T) {
	value := safeSystemParentACL()
	if err := AssessSystemParentACL(value); err != nil {
		t.Fatalf("safe inherited read-only ACEs refused: %v", err)
	}
	value.OwnerSID = journalSystemSID
	value.DACLProtected = true
	value.Entries = append(value.Entries, SystemParentACE{
		SID: "S-1-1-0", Type: systemParentDenyACE, Mask: 0x00000004,
	})
	if err := AssessSystemParentACL(value); err != nil {
		t.Fatalf("known deny and protected owner/DACL refused: %v", err)
	}
}

func TestSystemParentACLRejectsUnprivilegedParentMutations(t *testing.T) {
	tests := []struct {
		name string
		mutate func(*SystemParentACL)
	}{
		{"untrusted owner", func(v *SystemParentACL) { v.OwnerSID = "S-1-5-32-545" }},
		{"defaulted owner", func(v *SystemParentACL) { v.OwnerDefaulted = true }},
		{"missing DACL", func(v *SystemParentACL) { v.DACLPresent = false }},
		{"defaulted DACL", func(v *SystemParentACL) { v.DACLDefaulted = true }},
		{"empty DACL", func(v *SystemParentACL) { v.Entries = nil }},
		{"unknown ACE", func(v *SystemParentACL) { v.Entries[2].Type = 5 }},
		{"unknown flags", func(v *SystemParentACL) { v.Entries[2].Flags = 0x40 }},
		{"generic read", func(v *SystemParentACL) { v.Entries[2].Mask = 0x80000000 }},
		{"generic all", func(v *SystemParentACL) { v.Entries[2].Mask = 0x10000000 }},
		{"create subdirectory", func(v *SystemParentACL) { v.Entries[2].Mask |= 0x00000004 }},
		{"add file", func(v *SystemParentACL) { v.Entries[2].Mask |= 0x00000002 }},
		{"delete child", func(v *SystemParentACL) { v.Entries[2].Mask |= 0x00000040 }},
		{"delete parent", func(v *SystemParentACL) { v.Entries[2].Mask |= 0x00010000 }},
		{"write DACL", func(v *SystemParentACL) { v.Entries[2].Mask |= 0x00040000 }},
		{"write owner", func(v *SystemParentACL) { v.Entries[2].Mask |= 0x00080000 }},
		{"write attributes", func(v *SystemParentACL) { v.Entries[2].Mask |= 0x00000100 }},
		{"write EA", func(v *SystemParentACL) { v.Entries[2].Mask |= 0x00000010 }},
		{"inherit only write", func(v *SystemParentACL) { v.Entries[2].Flags = 0x08; v.Entries[2].Mask |= 0x00000004 }},
		{"creator owner write", func(v *SystemParentACL) { v.Entries[2].SID = "S-1-3-0"; v.Entries[2].Flags = 0x0b; v.Entries[2].Mask = journalParentFullControl }},
		{"untrusted domain trustee write", func(v *SystemParentACL) { v.Entries[2].SID = "S-1-5-21-12345-12345-12345-1111"; v.Entries[2].Mask = journalParentFullControl }},
		{"unknown SID", func(v *SystemParentACL) { v.Entries[2].SID = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := safeSystemParentACL()
			tc.mutate(&v)
			if err := AssessSystemParentACL(v); !errors.Is(err, ErrUnsafeSystemParentACL) {
				t.Fatalf("unsafe parent accepted: %+v, err=%v", v, err)
			}
		})
	}
}

func TestSystemParentACLDoesNotAllowDenyACEToConcealBroadAllow(t *testing.T) {
	value := safeSystemParentACL()
	value.Entries = append([]SystemParentACE{
		{SID: "S-1-5-32-545", Type: systemParentDenyACE, Mask: 0x00000004},
	}, value.Entries...)
	value.Entries[len(value.Entries)-1].Mask |= 0x00000004
	if err := AssessSystemParentACL(value); !errors.Is(err, ErrUnsafeSystemParentACL) {
		t.Fatalf("broad allow concealed by earlier deny: %v", err)
	}
}

func TestSystemParentACLRejectsUnboundedEntries(t *testing.T) {
	value := safeSystemParentACL()
	for len(value.Entries) <= systemParentMaxACEs {
		value.Entries = append(value.Entries, SystemParentACE{
			SID: journalSystemSID, Type: systemParentAllowACE, Mask: journalParentFullControl,
		})
	}
	if err := AssessSystemParentACL(value); !errors.Is(err, ErrUnsafeSystemParentACL) {
		t.Fatalf("unbounded ACL accepted: %v", err)
	}
}
