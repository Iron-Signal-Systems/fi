// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package freshinstall

import (
	"errors"
	"fmt"
)

// ErrUnqualifiedInstallerParentAccess means the observed effective Windows
// access is unavailable, denied, relies on privilege override, or fails a
// separate host/ACL/token precondition. It never permits an installer action.
var ErrUnqualifiedInstallerParentAccess = errors.New("FI v2 installed-state parent effective-access evidence is not sufficient")

const (
	installerParentCreateChild uint32 = 0x00000004 // FILE_ADD_SUBDIRECTORY
	installerParentReadControl uint32 = 0x00020000 // READ_CONTROL
)

// InstallerParentRight is one read-only native AccessCheck result. Requested
// contains an exact FILE_* / standard access right, not MAXIMUM_ALLOWED or
// an unmapped GENERIC_* right. Completed distinguishes a denied access check
// (a valid observation) from missing or inconclusive native evidence.
type InstallerParentRight struct {
	Requested uint32
	Completed bool
	Allowed bool
	Granted uint32
	PrivilegesUsed uint32
}

// InstallerParentAccessEvidence combines independently observed native token,
// OS parent identity, owner/DACL and exact-right AccessCheck results. None
// is an installed grant, issuer, approved action, or reusable capability.
type InstallerParentAccessEvidence struct {
	Token InstallerTokenEvidence
	SystemParent SystemParentEvidence
	ProgramDataACL SystemParentACL
	CreateChild InstallerParentRight
	ReadControl InstallerParentRight
}

// validateInstallerParentRight refuses unexplained AccessCheck outputs.
// An access denial is a valid native observation, but cannot satisfy a
// future installer precondition. Access obtained through a privilege rather
// than the checked discretionary rights is likewise not accepted here.
func validateInstallerParentRight(right InstallerParentRight, want uint32) error {
	if !right.Completed || right.Requested != want ||
		right.Requested == 0 || right.Requested & 0xf2000000 != 0 ||
		right.PrivilegesUsed != 0 {
		return fmt.Errorf("%w: incomplete, unrecognized or privilege-dependent right 0x%x",
			ErrUnqualifiedInstallerParentAccess, want)
	}
	if !right.Allowed || right.Granted & want != want ||
		right.Granted & ^want != 0 {
		return fmt.Errorf("%w: exact right 0x%x denied or granted mask inconsistent",
			ErrUnqualifiedInstallerParentAccess, want)
	}
	return nil
}

// AssessInstallerParentAccess is a diagnostic conjunction, not an
// authorization function. Token elevation, conservative shared ProgramData
// DACL exposure, native full-width directory identities, and real AccessCheck
// decisions must ALL pass. Even success cannot authenticate operator consent,
// an installation issuer or the continuous retained-handle transaction.
func AssessInstallerParentAccess(e InstallerParentAccessEvidence) error {
	if err:=AssessInstallerTokenEvidence(e.Token);err!=nil {
		return fmt.Errorf("%w: process token: %v",ErrUnqualifiedInstallerParentAccess,err)
	}
	if err:=AssessSystemParentEvidence(e.SystemParent);err!=nil {
		return fmt.Errorf("%w: native system parent identity: %v",ErrUnqualifiedInstallerParentAccess,err)
	}
	if err:=AssessSystemParentACL(e.ProgramDataACL);err!=nil {
		return fmt.Errorf("%w: shared ProgramData owner/DACL: %v",ErrUnqualifiedInstallerParentAccess,err)
	}
	if err:=validateInstallerParentRight(e.CreateChild,installerParentCreateChild);err!=nil{return err}
	if err:=validateInstallerParentRight(e.ReadControl,installerParentReadControl);err!=nil{return err}
	return nil
}
