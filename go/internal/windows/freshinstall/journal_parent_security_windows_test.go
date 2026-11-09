// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestNativeWindowsParentSecurityDescriptorStrictSDDL(t *testing.T) {
	const protectedSDDL = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	sd, err := windows.SecurityDescriptorFromString(protectedSDDL)
	if err != nil {
		t.Fatalf("parse canonical protected Windows SDDL: %v", err)
	}
	observed, err := journalParentSecurityFromDescriptor(sd)
	if err != nil {
		t.Fatalf("decode canonical native ACEs: %v", err)
	}
	if observed.OwnerSID != journalSystemSID ||
		!observed.DACLProtected || observed.DACLDefaulted ||
		!observed.DACLPresent || len(observed.Entries) != 2 {
		t.Fatalf("unexpected native descriptor interpretation: %+v", observed)
	}
	if err := ValidateJournalParentSecurity(observed); err != nil {
		t.Fatalf("native Windows full-control SYSTEM/Administrators ACL failed policy: %v", err)
	}
}

func TestNativeWindowsParentSecurityDescriptorRejectsUntrustedSDDL(t *testing.T) {
	tests := []struct {
		name string
		sddl string
	}{
		{"inherited/default inheritance", "O:SYG:SYD:(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"},
		{"Everyone granted full", "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;WD)"},
		{"additional broad access", "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;WD)"},
		{"weak owner", "O:WDG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"},
		{"no DACL entries", "O:SYG:SYD:P"},
		{"missing inherit flags", "O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)"},
		{"deny ACE", "O:SYG:SYD:P(D;OICI;FA;;;SY)(A;OICI;FA;;;BA)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatalf("test SDDL invalid: %v", err)
			}
			found, err := journalParentSecurityFromDescriptor(sd)
			if err == nil {
				err = ValidateJournalParentSecurity(found)
			}
			if !errors.Is(err, ErrUntrustedJournalParent) {
				t.Fatalf("unsafe native DACL accepted: %+v; error=%v", found, err)
			}
		})
	}
}

func TestNativeWindowsParentSecurityReadsOpenedDirectoryHandle(t *testing.T) {
	// This fixture is a normal Windows runner temp directory. It is not a
	// trusted/protected FI install parent and must not be used for deployment.
	dir := t.TempDir()
	if !filepath.IsAbs(dir) {
		t.Fatal("temp directory path is not absolute")
	}
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(
		name,
		windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		t.Fatalf("open temporary directory for read-only handle security discovery: %v", err)
	}
	defer windows.CloseHandle(h)
	state, err := inspectJournalParentSecurityByHandle(h)
	if err != nil {
		t.Fatalf("native descriptor was not readable by its retained directory handle: %v", err)
	}
	if state.OwnerSID == "" || !state.DACLPresent {
		t.Fatalf("native temp directory security was not extracted: %+v", state)
	}
	// Verification deliberately does not try to repair these untrusted
	// runner-specific ACLs. It does not grant a live installer authority.
	if err := verifyJournalParentHandle(windows.InvalidHandle); !errors.Is(err, ErrUntrustedJournalParent) {
		t.Fatalf("invalid native Windows handle was not rejected: %v", err)
	}
}

func TestNativeWindowsParentSecurityRejectsMissingDescriptor(t *testing.T) {
	if _, err := journalParentSecurityFromDescriptor(nil); !errors.Is(err, ErrUntrustedJournalParent) {
		t.Fatalf("nil native descriptor accepted: %v", err)
	}
	if _, err := inspectJournalParentSecurityByHandle(0); !errors.Is(err, ErrUntrustedJournalParent) {
		t.Fatalf("zero native handle accepted: %v", err)
	}
}
