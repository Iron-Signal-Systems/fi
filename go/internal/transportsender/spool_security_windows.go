// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package transportsender

import (
	"fmt"

	"golang.org/x/sys/windows"
)

const activeSpoolModifyMask = uint32(
	0x001301BF,
)

func replacementSpoolDACLSDDL() string {
	// OWNER RIGHTS (OW, S-1-3-4) is deliberate. Windows normally gives an
	// object owner implicit READ_CONTROL and WRITE_DAC. An OWNER RIGHTS ACE
	// suppresses those implicit owner permissions. The sender/collector account
	// remains the rotating directory owner, but receives only the operational
	// Modify mask here; WRITE_DAC and WRITE_OWNER are not in that mask.
	return fmt.Sprintf(
		"D:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x%08X;;;OW)",
		activeSpoolModifyMask,
	)
}

func secureReplacementSpoolDirectory(
	path string,
) error {
	descriptor, err := windows.SecurityDescriptorFromString(
		replacementSpoolDACLSDDL(),
	)
	if err != nil {
		return fmt.Errorf(
			"parse replacement FI spool DACL: %w",
			err,
		)
	}

	dacl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf(
			"read replacement FI spool DACL: %w",
			err,
		)
	}

	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf(
			"read replacement FI spool DACL control: %w",
			err,
		)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf(
			"replacement FI spool DACL is not protected",
		)
	}

	// The rollover-next directory was just created by FISender and is therefore
	// owned by its collector/sender gMSA. As owner, the process can establish
	// this DACL. The OWNER RIGHTS ACE then removes the owner's implicit
	// WRITE_DAC authority for steady-state operation.
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf(
			"apply protected replacement FI spool DACL to %s: %w",
			path,
			err,
		)
	}

	return nil
}
