// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package transportsender

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestReplacementSpoolDACLSDDLIsProtectedAndUsesOwnerRights(
	t *testing.T,
) {
	t.Parallel()

	sddl := replacementSpoolDACLSDDL()
	if !strings.Contains(
		sddl,
		";;;OW)",
	) {
		t.Fatalf(
			"replacement spool DACL does not contain OWNER RIGHTS ACE: %s",
			sddl,
		)
	}

	descriptor, err := windows.SecurityDescriptorFromString(
		sddl,
	)
	if err != nil {
		t.Fatalf(
			"parse replacement spool DACL: %v",
			err,
		)
	}

	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatalf(
			"read replacement spool DACL control: %v",
			err,
		)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal(
			"replacement spool DACL is not protected",
		)
	}

	if activeSpoolModifyMask&
		uint32(
			windows.WRITE_DAC|
				windows.WRITE_OWNER,
		) != 0 {
		t.Fatalf(
			"active spool Modify mask unexpectedly includes ACL-administration rights: 0x%08X",
			activeSpoolModifyMask,
		)
	}
}
