// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package freshinstall

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnsafeSystemParentACL means that a read-only descriptor observation
// cannot satisfy FI's conservative parent-access policy. It is not a reason
// to modify an existing Windows ACL. A future installer must fail closed.
var ErrUnsafeSystemParentACL = errors.New("FI v2 system parent owner/DACL has untrusted or unknown access")

const (
	systemParentAllowACE uint8 = 0
	systemParentDenyACE  uint8 = 1

	// ACE_HEADER.AceFlags: OI|CI|NP|IO|ID. Callback, audit and unknown ACE
	// types are rejected at the native decoder; unknown flags fail here.
	systemParentKnownACEFlags uint8 = 0x1f

	// Only FILE_LIST_DIRECTORY, FILE_READ_EA, FILE_TRAVERSE,
	// FILE_READ_ATTRIBUTES, READ_CONTROL and SYNCHRONIZE are benign for a
	// nonprivileged trustee at this bootstrap parent boundary.
	systemParentBenignReadMask uint32 = 0x001200a9

	// A generic mask is not accepted as evidence of known effective rights.
	// These are GENERIC_READ/WRITE/EXECUTE/ALL, not file-specific rights.
	systemParentGenericMask uint32 = 0xf0000000
	systemParentMaxACEs = 64
)

// SystemParentACE represents an observed native allow/deny ACE. The SID
// must come from GetSecurityInfo on the retained directory handle, not
// from caller-supplied configuration, when assessing a real Windows object.
type SystemParentACE struct {
	SID string
	Type uint8
	Flags uint8
	Mask uint32
}

// SystemParentACL is read-only access evidence for either the volume root
// or the shared ProgramData directory. A protected DACL is not mandatory:
// system directories legitimately inherit ACLs from the volume root.
// A NULL or missing DACL, defaulted owner/DACL, or unknown ACE is unsafe.
type SystemParentACL struct {
	OwnerSID string
	OwnerDefaulted bool
	DACLPresent bool
	DACLDefaulted bool
	DACLProtected bool
	Entries []SystemParentACE
}

// AssessSystemParentACL is intentionally a conservative exposure test, NOT
// a Windows AccessCheck implementation and NOT installation authorization.
//
// Owner SYSTEM or BUILTIN Administrators is required because an owner may
// normally change the DACL regardless of allow ACEs. All ACEs must be simple
// Windows allow/deny ACEs with known flags/masks. No trustee except SYSTEM
// or BUILTIN Administrators may receive a write, create, delete, security
// descriptor or owner-changing permission, even if inherited or marked
// INHERIT_ONLY: permissive descendant ACLs cannot silently be assumed safe.
//
// This deliberately may reject stock ProgramData layouts that grant ordinary
// users special folder-creation rights. Never "fix" an existing system
// directory to make this assessment pass; design trusted issuer/provenance
// and transaction handling separately before enabling installer mutation.
func AssessSystemParentACL(value SystemParentACL) error {
	switch value.OwnerSID {
	case journalSystemSID, journalAdministratorsSID:
	default:
		return fmt.Errorf("%w: directory owner %q is not SYSTEM/Administrators", ErrUnsafeSystemParentACL, value.OwnerSID)
	}
	if value.OwnerDefaulted || !value.DACLPresent || value.DACLDefaulted {
		return fmt.Errorf("%w: missing/null/defaulted owner or DACL", ErrUnsafeSystemParentACL)
	}
	if len(value.Entries) == 0 || len(value.Entries) > systemParentMaxACEs {
		return fmt.Errorf("%w: empty or excessive ACL (%d ACEs)", ErrUnsafeSystemParentACL, len(value.Entries))
	}
	for i, ace := range value.Entries {
		if ace.Type != systemParentAllowACE && ace.Type != systemParentDenyACE {
			return fmt.Errorf("%w: unsupported ACE type %d at index %d", ErrUnsafeSystemParentACL, ace.Type, i)
		}
		if ace.Flags & ^systemParentKnownACEFlags != 0 {
			return fmt.Errorf("%w: unknown ACE flags at index %d", ErrUnsafeSystemParentACL, i)
		}
		if ace.SID == "" || len(ace.SID) > 184 || !strings.HasPrefix(ace.SID, "S-1-") {
			return fmt.Errorf("%w: missing/noncanonical trustee at index %d", ErrUnsafeSystemParentACL, i)
		}
		if ace.Mask & systemParentGenericMask != 0 {
			return fmt.Errorf("%w: generic rights not expanded at index %d", ErrUnsafeSystemParentACL, i)
		}
		// A DENY does not erase a potentially risky ALLOW elsewhere. Reject
		// broad grants without trying to emulate Windows token evaluation.
		if ace.Type == systemParentAllowACE &&
			ace.SID != journalSystemSID && ace.SID != journalAdministratorsSID &&
			ace.Mask & ^systemParentBenignReadMask != 0 {
			return fmt.Errorf("%w: nonprivileged trustee %s has possible create/write/delete/owner rights at ACE %d, mask=0x%08x",
				ErrUnsafeSystemParentACL, ace.SID, i, ace.Mask)
		}
	}
	return nil
}
