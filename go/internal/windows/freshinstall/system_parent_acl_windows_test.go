// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

func TestSystemParentNativeACLDecodesExplicitAndInheritedRights(t *testing.T) {
	// Native SDDL exercises the actual Windows SECURITY_DESCRIPTOR/ACE
	// decoder. No Windows system directory ACL is ever changed.
	const safeSDDL = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;ID;0x001200a9;;;BU)"
	sd, err := windows.SecurityDescriptorFromString(safeSDDL)
	if err != nil {
		t.Fatalf("Windows SDDL parser rejected safe native ACL fixture: %v", err)
	}
	found, err := systemParentACLFromDescriptor(sd)
	if err != nil {
		t.Fatalf("native ACE decode failed: %v", err)
	}
	if len(found.Entries) != 3 || found.OwnerSID != journalSystemSID || !found.DACLProtected {
		t.Fatalf("native owner/ACE information not preserved: %+v", found)
	}
	if err := AssessSystemParentACL(found); err != nil {
		t.Fatalf("safe native SDDL failed pure exposure policy: %v", err)
	}
}

func TestSystemParentNativeACLRejectsUnsafeWindowsDescriptors(t *testing.T) {
	for _, tc := range []struct {
		name string
		sddl string
	}{
		{"Users can create subdirectories", "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x00000004;;;BU)"},
		{"Everyone full control", "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FA;;;WD)"},
		{"unprivileged owner", "O:BUG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"},
		{"unknown explicit rights", "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x01000000;;;BU)"},
		{"generic read mask", "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;GR;;;BU)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatalf("invalid test SDDL fixture: %v", err)
			}
			found, err := systemParentACLFromDescriptor(sd)
			if err == nil {
				err = AssessSystemParentACL(found)
			}
			if !errors.Is(err, ErrUnsafeSystemParentACL) {
				t.Fatalf("unsafe native descriptor accepted: %+v err=%v", found, err)
			}
		})
	}
}

func TestSystemParentNativeACLRejectsMissingDescriptorAndHandle(t *testing.T) {
	if _, err := systemParentACLFromDescriptor(nil); !errors.Is(err, ErrUnsafeSystemParentACL) {
		t.Fatalf("nil native SECURITY_DESCRIPTOR accepted: %v", err)
	}
	for _, handle := range []windows.Handle{0, windows.InvalidHandle} {
		if _, err := inspectSystemParentACLByHandle(handle); !errors.Is(err, ErrUnsafeSystemParentACL) {
			t.Fatalf("invalid native ACL handle accepted: %v", err)
		}
	}
}

func TestActualWindowsSystemParentACLInspectionRemainsReadOnly(t *testing.T) {
	p, err := inspectNativeSystemProgramData()
	if err != nil {
		t.Fatalf("read-only system directory identity observation: %v", err)
	}
	defer p.Close()

	// Windows deployments vary in inherited ACEs and ProgramData's
	// ordinary-user create rights. A refusal by strict policy is not a
	// code failure or native install success; it is a real BLOCKED finding.
	// No ACL is repaired, and the fixture never attempts an installation.
	observed, inspectErr := p.inspectParentAccess()
	if inspectErr != nil {
		if !errors.Is(inspectErr, ErrUnsafeSystemParentACL) {
			t.Fatalf("unclassified native ACL inspection failure: %v", inspectErr)
		}
		t.Logf("OS root/ProgramData ACL observation unavailable or unsupported; installation blocked: %v", inspectErr)
		return
	}
	for _, item := range []struct{
		name string
		acl SystemParentACL
	}{
		{"volume root", observed.Root},
		{"common ProgramData", observed.ProgramData},
	} {
		err := AssessSystemParentACL(item.acl)
		if err != nil && !errors.Is(err, ErrUnsafeSystemParentACL) {
			t.Fatalf("unclassified native ACL policy error for %s: %v", item.name, err)
		}
		t.Logf("read-only %s ACL owner=%s ACEs=%d exposure_result=%v",
			item.name, item.acl.OwnerSID, len(item.acl.Entries), err)
	}
	// This end-to-end verdict may be BLOCKED on stock runners. Never
	// interpret it as installer authorization even when it returns nil.
	if err := p.assessParentAccess(); err != nil &&
		!errors.Is(err, ErrUnsafeSystemParentACL) {
		t.Fatalf("native exposure assessment returned unclassified error: %v", err)
	}
}
