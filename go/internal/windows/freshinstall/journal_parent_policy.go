// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package freshinstall includes the strictly read-only authorization policy
// for a future creation-only installer's journal-parent directory.
//
// A matching DACL is NOT evidence of a trusted issuer, elevated operator,
// legitimate host, unmodified ancestor chain or exclusive installer lease.
// The Windows service and installer MUST NOT use this as a standalone grant.
package freshinstall

import (
	"errors"
	"fmt"
)

const (
	// Canonical well-known Windows SIDs. These identify local principals,
	// never names obtained through locale-dependent account lookup.
	journalSystemSID         = "S-1-5-18"
	journalAdministratorsSID = "S-1-5-32-544"

	// FILE_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF.
	// An exact permission set is required, not merely access to create a file.
	// Extra/inconsistent masks and generic unexpanded rights fail closed.
	journalParentFullControl uint32 = 0x001F01FF

	// Both directory and file children must inherit the restricted trustees.
	// INHERITED, INHERIT_ONLY, NO_PROPAGATE, audit and unexpected flags fail.
	journalParentInheritFlags uint8 = 0x03

	journalAccessAllowedACE uint8 = 0
)

var ErrUntrustedJournalParent = errors.New("FI v2 journal parent DACL/owner is not an approved protected boundary")

// JournalParentACE is an independently observed, explicit Windows ACE. Its
// fields must be extracted from a verified native SECURITY_DESCRIPTOR, not
// from a caller's assertion, when used to accept an actual installation.
type JournalParentACE struct {
	SID   string
	Type  uint8
	Flags uint8
	Mask  uint32
}

// JournalParentSecurity is the bounded policy input. Absence, a null DACL,
// a defaulted DACL, inherited ACEs, and unknown ACE forms are not acceptable.
type JournalParentSecurity struct {
	OwnerSID      string
	OwnerDefaulted bool
	DACLPresent   bool
	DACLProtected bool
	DACLDefaulted bool
	Entries       []JournalParentACE
}

// ValidateJournalParentSecurity deliberately requires one canonical
// inheritable full-control ACE for SYSTEM and one for BUILTIN Administrators,
// with no other entries. A file journal created beneath it must separately
// have its effective DACL verified after creation and at service restart.
func ValidateJournalParentSecurity(value JournalParentSecurity) error {
	switch value.OwnerSID {
	case journalSystemSID, journalAdministratorsSID:
		// Ownership must not be granted to a domain principal or arbitrary
		// local user, even one running in an elevated interactive session.
	default:
		return fmt.Errorf("%w: unacceptable owner SID %q", ErrUntrustedJournalParent, value.OwnerSID)
	}
	if value.OwnerDefaulted {
		return fmt.Errorf("%w: defaulted owner is not accepted", ErrUntrustedJournalParent)
	}
	if !value.DACLPresent || !value.DACLProtected || value.DACLDefaulted {
		return fmt.Errorf("%w: explicit nondefaulted protected DACL required", ErrUntrustedJournalParent)
	}
	if len(value.Entries) != 2 {
		return fmt.Errorf("%w: exactly two explicit privileged ACEs required, got %d", ErrUntrustedJournalParent, len(value.Entries))
	}
	seenSystem, seenAdministrators := false, false
	for index, ace := range value.Entries {
		if ace.Type != journalAccessAllowedACE || ace.Flags != journalParentInheritFlags ||
			ace.Mask != journalParentFullControl {
			return fmt.Errorf("%w: noncanonical ACE at index %d (type=%d flags=0x%02x mask=0x%08x)",
				ErrUntrustedJournalParent, index, ace.Type, ace.Flags, ace.Mask)
		}
		switch ace.SID {
		case journalSystemSID:
			if seenSystem {
				return fmt.Errorf("%w: duplicate SYSTEM ACE", ErrUntrustedJournalParent)
			}
			seenSystem = true
		case journalAdministratorsSID:
			if seenAdministrators {
				return fmt.Errorf("%w: duplicate Administrators ACE", ErrUntrustedJournalParent)
			}
			seenAdministrators = true
		default:
			return fmt.Errorf("%w: unapproved ACE SID %q", ErrUntrustedJournalParent, ace.SID)
		}
	}
	if !seenSystem || !seenAdministrators {
		return fmt.Errorf("%w: SYSTEM and Administrators must each have explicit inheritance", ErrUntrustedJournalParent)
	}
	return nil
}
