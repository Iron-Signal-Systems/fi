// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestDesiredProtectedSpoolSDDLUsesOwnerRightsBoundary(
	t *testing.T,
) {
	t.Parallel()

	const owner = "S-1-5-21-1-2-3-4"
	sddl := desiredProtectedSpoolSDDL(
		owner,
	)

	if !strings.Contains(
		sddl,
		"O:"+owner,
	) {
		t.Fatalf(
			"spool SDDL owner mismatch: %s",
			sddl,
		)
	}
	if !strings.Contains(
		sddl,
		";;;OW)",
	) {
		t.Fatalf(
			"spool SDDL does not contain OWNER RIGHTS ACE: %s",
			sddl,
		)
	}

	descriptor, err := windows.SecurityDescriptorFromString(
		sddl,
	)
	if err != nil {
		t.Fatalf(
			"parse spool SDDL: %v",
			err,
		)
	}

	control, _, err := descriptor.Control()
	if err != nil {
		t.Fatalf(
			"read spool SDDL control: %v",
			err,
		)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal(
			"spool DACL is not protected",
		)
	}

	if fileModifyMask&
		uint32(
			windows.WRITE_DAC|
				windows.WRITE_OWNER,
		) != 0 {
		t.Fatalf(
			"spool Modify mask unexpectedly includes ACL-administration rights: 0x%08X",
			fileModifyMask,
		)
	}
}
