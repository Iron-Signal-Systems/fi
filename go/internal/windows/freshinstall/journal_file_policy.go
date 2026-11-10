// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package freshinstall

import (
	"errors"
	"fmt"
)

// ErrUntrustedJournalFile prevents a newly-created journal from being
// acknowledged as reserved if its actual handle lacks the required security
// descriptor. A failed check leaves an in-doubt file; do NOT delete or retry.
var ErrUntrustedJournalFile = errors.New("FI v2 creation journal file has untrusted native owner or DACL")

const (
	journalFileInheritedACE uint8 = 0x10
	journalFilePermittedACEFlags uint8 = journalFileInheritedACE | journalParentInheritFlags
)

// ValidateCreationJournalFileSecurity is a narrow effective-DACL check,
// intentionally distinct from ValidateJournalParentSecurity. The parent
// MUST have exactly two explicit inheritable SYSTEM/Administrators ACEs. The
// new file MUST have exactly those two inherited full-control ACEs, no
// additional rights, and owner SYSTEM or Administrators. The native caller
// supplies a descriptor extracted from the newly created file HANDLE.
// Because this is a file, inherited OI/CI flags may be absent or retained;
// no unexpected ACE flags, inherit-only ACEs, generic rights or principals
// are accepted.
//
// Even a matching descriptor is not proof of trusted issuer, host identity,
// authentic approval or protected ancestor provenance.
func ValidateCreationJournalFileSecurity(value JournalParentSecurity) error {
	switch value.OwnerSID {
	case journalSystemSID, journalAdministratorsSID:
		// A canonical privileged owner must be observed on the file itself.
	default:
		return fmt.Errorf("%w: unexpected journal owner %q", ErrUntrustedJournalFile, value.OwnerSID)
	}
	if value.OwnerDefaulted || !value.DACLPresent || value.DACLDefaulted {
		return fmt.Errorf("%w: owner/DACL missing or defaulted", ErrUntrustedJournalFile)
	}
	if len(value.Entries) != 2 {
		return fmt.Errorf("%w: expected exactly two inherited privileged ACEs, found %d",
			ErrUntrustedJournalFile, len(value.Entries))
	}
	seenSystem, seenAdministrators := false, false
	for i, ace := range value.Entries {
		if ace.Type != journalAccessAllowedACE ||
			ace.Mask != journalParentFullControl ||
			ace.Flags&journalFileInheritedACE == 0 ||
			ace.Flags&^journalFilePermittedACEFlags != 0 {
			return fmt.Errorf("%w: unexpected ACE type, mask or flags at index %d",
				ErrUntrustedJournalFile, i)
		}
		switch ace.SID {
		case journalSystemSID:
			if seenSystem {
				return fmt.Errorf("%w: duplicate SYSTEM ACE", ErrUntrustedJournalFile)
			}
			seenSystem = true
		case journalAdministratorsSID:
			if seenAdministrators {
				return fmt.Errorf("%w: duplicate Administrators ACE", ErrUntrustedJournalFile)
			}
			seenAdministrators = true
		default:
			return fmt.Errorf("%w: unexpected journal ACE trustee %q", ErrUntrustedJournalFile, ace.SID)
		}
	}
	if !seenSystem || !seenAdministrators {
		return fmt.Errorf("%w: SYSTEM and Administrators inherited rights required", ErrUntrustedJournalFile)
	}
	return nil
}
