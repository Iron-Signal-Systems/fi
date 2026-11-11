// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// inspectSystemParentACLByHandle reads the exact directory handle's native
// owner and DACL. Unlike the strict FI-Installer child policy, ordinary
// system directories may legitimately contain inherited ACEs and read-only
// nonprivileged users. This decoder accepts only simple ALLOW/DENY ACEs;
// callback/object/conditional/unknown ACEs cause a fail-closed result.
//
// No path lookup, token change, SetSecurityInfo, ACL repair or mutation
// occurs. An administrator changing both host state and this descriptor is
// outside the authority that this read-only observation could establish.
func inspectSystemParentACLByHandle(handle windows.Handle) (SystemParentACL, error) {
	if handle == 0 || handle == windows.InvalidHandle {
		return SystemParentACL{}, fmt.Errorf("%w: missing parent security handle", ErrUnsafeSystemParentACL)
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return SystemParentACL{}, fmt.Errorf("%w: GetSecurityInfo owner/DACL: %v", ErrUnsafeSystemParentACL, err)
	}
	return systemParentACLFromDescriptor(descriptor)
}

// The SECURITY_DESCRIPTOR and ACE pointers originate in the same native
// descriptor buffer. Keep the descriptor alive through every SID access.
func systemParentACLFromDescriptor(sd *windows.SECURITY_DESCRIPTOR) (SystemParentACL, error) {
	if sd == nil || !sd.IsValid() {
		return SystemParentACL{}, fmt.Errorf("%w: missing or invalid native SECURITY_DESCRIPTOR", ErrUnsafeSystemParentACL)
	}
	defer runtime.KeepAlive(sd)

	owner, ownerDefaulted, err := sd.Owner()
	if err != nil || owner == nil || !owner.IsValid() {
		return SystemParentACL{}, fmt.Errorf("%w: native owner missing or malformed: %v", ErrUnsafeSystemParentACL, err)
	}
	control, _, err := sd.Control()
	if err != nil {
		return SystemParentACL{}, fmt.Errorf("%w: read DACL control: %v", ErrUnsafeSystemParentACL, err)
	}
	found := SystemParentACL{
		OwnerSID: owner.String(),
		OwnerDefaulted: ownerDefaulted,
		DACLPresent: control&windows.SE_DACL_PRESENT != 0,
		DACLProtected: control&windows.SE_DACL_PROTECTED != 0,
	}
	if !found.DACLPresent {
		return found, fmt.Errorf("%w: native descriptor has no DACL", ErrUnsafeSystemParentACL)
	}
	dacl, daclDefaulted, err := sd.DACL()
	if err != nil || dacl == nil {
		return found, fmt.Errorf("%w: native directory DACL is null/unavailable: %v", ErrUnsafeSystemParentACL, err)
	}
	found.DACLDefaulted = daclDefaulted
	if dacl.AceCount == 0 || dacl.AceCount > systemParentMaxACEs {
		return found, fmt.Errorf("%w: native DACL ACE count %d outside 1..%d",
			ErrUnsafeSystemParentACL, dacl.AceCount, systemParentMaxACEs)
	}
	found.Entries = make([]SystemParentACE, 0, dacl.AceCount)
	for index := uint16(0); index < dacl.AceCount; index++ {
		var nativeACE *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &nativeACE); err != nil || nativeACE == nil {
			return found, fmt.Errorf("%w: GetAce index %d: %v", ErrUnsafeSystemParentACL, index, err)
		}
		if nativeACE.Header.AceSize < uint16(unsafe.Sizeof(windows.ACCESS_ALLOWED_ACE{})) ||
			(nativeACE.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE &&
				nativeACE.Header.AceType != windows.ACCESS_DENIED_ACE_TYPE) {
			return found, fmt.Errorf("%w: unsupported or malformed native ACE type/size at %d", ErrUnsafeSystemParentACL, index)
		}
		principal := (*windows.SID)(unsafe.Pointer(&nativeACE.SidStart))
		if principal == nil || !principal.IsValid() {
			return found, fmt.Errorf("%w: malformed trustee SID in ACE %d", ErrUnsafeSystemParentACL, index)
		}
		found.Entries = append(found.Entries, SystemParentACE{
			SID: principal.String(),
			Type: nativeACE.Header.AceType,
			Flags: nativeACE.Header.AceFlags,
			Mask: uint32(nativeACE.Mask),
		})
	}
	return found, nil
}

// systemParentAccessObservation is a snapshot of root and ProgramData access
// descriptors, not a grant or a reusable policy authorization token.
type systemParentAccessObservation struct {
	Root SystemParentACL
	ProgramData SystemParentACL
}

// inspectParentAccess binds each descriptor read to the previously retained
// root and ProgramData native file IDs and freshly rechecks namespace names
// before and after access observations. These checks cannot prevent all
// inter-call races or prove a trusted Windows issuer, so installer apply is
// deliberately NOT wired to this function.
func (p *nativeSystemParentInspection) inspectParentAccess() (systemParentAccessObservation, error) {
	if p == nil {
		return systemParentAccessObservation{}, ErrUnsafeSystemParentACL
	}
	if err := p.verifyRetained(); err != nil {
		return systemParentAccessObservation{}, fmt.Errorf("%w: before owner/DACL observation: %v", ErrUnsafeSystemParentACL, err)
	}
	root, err := inspectSystemParentACLByHandle(p.root.handle)
	if err != nil {
		return systemParentAccessObservation{}, fmt.Errorf("%w: system volume root: %v", ErrUnsafeSystemParentACL, err)
	}
	programData, err := inspectSystemParentACLByHandle(p.programData.handle)
	if err != nil {
		return systemParentAccessObservation{}, fmt.Errorf("%w: shared ProgramData: %v", ErrUnsafeSystemParentACL, err)
	}
	if err := p.verifyRetained(); err != nil {
		return systemParentAccessObservation{}, fmt.Errorf("%w: after owner/DACL observation: %v", ErrUnsafeSystemParentACL, err)
	}
	return systemParentAccessObservation{Root: root, ProgramData: programData}, nil
}

// assessParentAccess is separate from inspection so callers cannot confuse
// "we decoded the ACL" with "this ACL passes the conservative exposure rule".
// A successful result still cannot authorize installer creation or services.
func (p *nativeSystemParentInspection) assessParentAccess() error {
	observed, err := p.inspectParentAccess()
	if err != nil {
		return err
	}
	if err := AssessSystemParentACL(observed.Root); err != nil {
		return fmt.Errorf("%w: system volume root: %v", ErrUnsafeSystemParentACL, err)
	}
	if err := AssessSystemParentACL(observed.ProgramData); err != nil {
		return fmt.Errorf("%w: shared ProgramData: %v", ErrUnsafeSystemParentACL, err)
	}
	return p.verifyRetained()
}
