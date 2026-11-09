// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// inspectJournalParentSecurityByHandle reads the object security descriptor
// from an already-opened native directory HANDLE, NOT by a second path lookup.
// The caller must keep the handle open to prevent directory rename, must
// independently prove it is the expected non-reparse directory, and must
// validate ancestor ownership/alias controls before trusting this evidence.
//
// This function is read-only, unexported and does not grant install authority.
func inspectJournalParentSecurityByHandle(handle windows.Handle) (JournalParentSecurity, error) {
	if handle == 0 || handle == windows.InvalidHandle {
		return JournalParentSecurity{}, fmt.Errorf("%w: missing native journal directory handle", ErrUntrustedJournalParent)
	}
	descriptor, err := windows.GetSecurityInfo(
		handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return JournalParentSecurity{}, fmt.Errorf("%w: read native owner/DACL: %v", ErrUntrustedJournalParent, err)
	}
	return journalParentSecurityFromDescriptor(descriptor)
}

// journalParentSecurityFromDescriptor allows isolated Windows SDDL tests of
// actual Windows ACE decoding without installing or modifying any host DACL.
func journalParentSecurityFromDescriptor(sd *windows.SECURITY_DESCRIPTOR) (JournalParentSecurity, error) {
	if sd == nil || !sd.IsValid() {
		return JournalParentSecurity{}, fmt.Errorf("%w: missing or invalid security descriptor", ErrUntrustedJournalParent)
	}
	// GetAce returns pointers into the security descriptor's backing memory.
	// Retain the Go-managed self-relative descriptor for their entire use.
	defer runtime.KeepAlive(sd)

	owner, ownerDefaulted, err := sd.Owner()
	if err != nil || owner == nil {
		return JournalParentSecurity{}, fmt.Errorf("%w: missing native security owner: %v", ErrUntrustedJournalParent, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		return JournalParentSecurity{}, fmt.Errorf("%w: read DACL control flags: %v", ErrUntrustedJournalParent, err)
	}
	out := JournalParentSecurity{
		OwnerSID: owner.String(),
		OwnerDefaulted: ownerDefaulted,
		DACLPresent: control&windows.SE_DACL_PRESENT != 0,
		DACLProtected: control&windows.SE_DACL_PROTECTED != 0,
	}
	if !out.DACLPresent {
		return out, fmt.Errorf("%w: DACL is not present", ErrUntrustedJournalParent)
	}
	dacl, daclDefaulted, err := sd.DACL()
	if err != nil || dacl == nil {
		return out, fmt.Errorf("%w: DACL is null or unavailable: %v", ErrUntrustedJournalParent, err)
	}
	out.DACLDefaulted = daclDefaulted
	// Fail before decoding an unexpectedly long list. There is no reason to
	// process a larger DACL under the exact two-ACE parent security contract.
	if dacl.AceCount != 2 {
		return out, fmt.Errorf("%w: native journal directory DACL contains %d ACEs, expected exactly two",
			ErrUntrustedJournalParent, dacl.AceCount)
	}
	out.Entries = make([]JournalParentACE, 0, 2)
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil || ace == nil {
			return JournalParentSecurity{}, fmt.Errorf("%w: read journal ACE %d: %v", ErrUntrustedJournalParent, index, err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceSize < uint16(unsafe.Sizeof(windows.ACCESS_ALLOWED_ACE{})) {
			return JournalParentSecurity{}, fmt.Errorf("%w: unexpected type/size for ACE %d", ErrUntrustedJournalParent, index)
		}
		principal := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if principal == nil || !principal.IsValid() {
			return JournalParentSecurity{}, fmt.Errorf("%w: invalid principal SID in ACE %d", ErrUntrustedJournalParent, index)
		}
		out.Entries = append(out.Entries, JournalParentACE{
			Type: ace.Header.AceType,
			Flags: ace.Header.AceFlags,
			Mask: uint32(ace.Mask),
			SID: principal.String(),
		})
	}
	return out, nil
}

// verifyJournalParentHandle is a read-only check to be called after the
// existing native handle/path/reparse validation and before future bootstrap
// accepts a journal location. It is intentionally NOT wired into a production
// installer until protected-parent creation and ancestry trust are engineered.
func verifyJournalParentHandle(handle windows.Handle) error {
	value, err := inspectJournalParentSecurityByHandle(handle)
	if err != nil {
		return err
	}
	if err := ValidateJournalParentSecurity(value); err != nil {
		return err
	}
	return nil
}

// All native ACL errors are fatal rather than treated as empty or defaulted
// security. Do not follow a caller-provided path to repair these failures.
var _ = errors.Is
