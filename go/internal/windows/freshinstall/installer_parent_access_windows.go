// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var nativeInstallerAccessCheckProc = windows.NewLazySystemDLL("advapi32.dll").NewProc("AccessCheck")

// The four DWORDs must match the Windows GENERIC_MAPPING ABI. DesiredAccess
// always uses exact FILE_* or standard bits, never MAXIMUM_ALLOWED or GENERIC.
// The mapping is still required to evaluate generic ACEs correctly.
type nativeInstallerFileMapping struct {
	GenericRead uint32
	GenericWrite uint32
	GenericExecute uint32
	GenericAll uint32
}

var nativeInstallerFileRights = nativeInstallerFileMapping{
	GenericRead: 0x00120089,
	GenericWrite: 0x00120116,
	GenericExecute: 0x001200a0,
	GenericAll: 0x001f01ff,
}

// nativeCheckInstallerRight performs Windows AccessCheck against an actual
// security descriptor and an IMPERSONATION-FORMAT, QUERY-ONLY token handle.
// It never installs the token on any thread and never adjusts privileges.
// The security descriptor may be from GetSecurityInfo on a retained object.
//
// GetSecurityInfo returns a self-relative descriptor. AccessCheck is given
// an absolute descriptor via ToAbsolute, retaining the native owner, group
// and DACL. A bounded PRIVILEGE_SET buffer is provided; unexpected native
// output or a privilege-assisted access result is never an installer grant.
func nativeCheckInstallerRight(sd *windows.SECURITY_DESCRIPTOR, checkToken windows.Token, want uint32) (InstallerParentRight,error) {
	if sd==nil || !sd.IsValid() || checkToken==0 ||
		windows.Handle(checkToken)==windows.InvalidHandle ||
		(want!=installerParentCreateChild && want!=installerParentReadControl) {
		return InstallerParentRight{},fmt.Errorf("%w: missing descriptor/token or unsupported exact right",ErrUnqualifiedInstallerParentAccess)
	}
	absolute,err:=sd.ToAbsolute()
	if err!=nil || absolute==nil || !absolute.IsValid() {
		return InstallerParentRight{},fmt.Errorf("%w: convert actual security descriptor to absolute form: %v",ErrUnqualifiedInstallerParentAccess,err)
	}
	defer runtime.KeepAlive(absolute)
	// A dedicated 8-byte-aligned buffer avoids unaligned native structure
	// access; AccessCheck reports ERROR_INSUFFICIENT_BUFFER if this fixed
	// budget is inadequate. We fail closed and never grow it indefinitely.
	var privilegeSet [128]uint64
	privilegeSetLen:=uint32(unsafe.Sizeof(privilegeSet))
	var granted,status uint32
	mapping:=nativeInstallerFileRights
	r,_,nativeErr:=nativeInstallerAccessCheckProc.Call(
		uintptr(unsafe.Pointer(absolute)),
		uintptr(checkToken),
		uintptr(want),
		uintptr(unsafe.Pointer(&mapping)),
		uintptr(unsafe.Pointer(&privilegeSet[0])),
		uintptr(unsafe.Pointer(&privilegeSetLen)),
		uintptr(unsafe.Pointer(&granted)),
		uintptr(unsafe.Pointer(&status)),
	)
	runtime.KeepAlive(sd)
	runtime.KeepAlive(privilegeSet)
	if r==0 {
		return InstallerParentRight{},fmt.Errorf("%w: AccessCheck failed for right 0x%x: %v",ErrUnqualifiedInstallerParentAccess,want,nativeErr)
	}
	if privilegeSetLen<8 || privilegeSetLen>uint32(unsafe.Sizeof(privilegeSet)) ||
		status>1 || (status==0 && granted!=0) ||
		(status==1 && granted&want!=want) || granted & ^want!=0 {
		return InstallerParentRight{},fmt.Errorf("%w: native AccessCheck returned inconsistent status, access or privilege-set length",
			ErrUnqualifiedInstallerParentAccess)
	}
	// Windows PRIVILEGE_SET begins with DWORD PrivilegeCount and DWORD
	// Control; any nonzero count is observed but not an acceptable
	// unqualified DACL permission in our separate policy.
	privilegeHeader:=unsafe.Slice((*byte)(unsafe.Pointer(&privilegeSet[0])),8)
	used:=binary.LittleEndian.Uint32(privilegeHeader[:4])
	if used>maxInstallerPrivileges || (used>0 && privilegeSetLen<8+used*12) {
		return InstallerParentRight{},fmt.Errorf("%w: malformed AccessCheck PRIVILEGE_SET",ErrUnqualifiedInstallerParentAccess)
	}
	return InstallerParentRight{
		Requested:want,Completed:true,Allowed:status==1,Granted:granted,PrivilegesUsed:used,
	},nil
}

// nativeAccessCheckTokenFromProcess creates a STRICTLY TOKEN_QUERY-capable
// impersonation-FORMAT token for the AccessCheck API. Windows AccessCheck
// requires this token format; it is NOT impersonation of the current thread.
// No TOKEN_IMPERSONATE, TOKEN_ADJUST_PRIVILEGES, TOKEN_ASSIGN_PRIMARY or
// service/process token replacement access is granted. Both handles close.
func nativeAccessCheckTokenFromProcess() (windows.Token,error) {
	var process windows.Token
	if err:=windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE,&process);err!=nil {
		return 0,fmt.Errorf("%w: open process token with query/duplicate only: %v",ErrUnqualifiedInstallerParentAccess,err)
	}
	defer process.Close()
	var checkToken windows.Token
	// SecurityIdentification=1: enough for the Windows access decision,
	// never the SecurityImpersonation/Delegation power for thread identity.
	const securityIdentification uint32 = 1
	const tokenImpersonation uint32 = 2
	if err:=windows.DuplicateTokenEx(process,windows.TOKEN_QUERY,nil,
		securityIdentification,tokenImpersonation,&checkToken);err!=nil {
		return 0,fmt.Errorf("%w: create query-only AccessCheck token: %v",ErrUnqualifiedInstallerParentAccess,err)
	}
	return checkToken,nil
}

// inspectInstallerProgramDataAccess collects actual Windows AccessCheck
// decisions for the intended process against a descriptor read FROM THE
// RETAINED ProgramData HANDLE. It deliberately does not call
// AssessInstallerParentAccess, since stock runner tokens/ACLs may be
// ineligible yet still provide valuable actual access evidence.
//
// The source parent is the exact object retained by the separate system
// identity observer. Revalidation before and after catches detected changes,
// not all concurrent malicious DACL/namespace races. The current native
// source remains disconnected from the v2 installer and protected grant.
func (p *nativeSystemParentInspection) inspectInstallerProgramDataAccess() (InstallerParentAccessEvidence,error) {
	if p==nil {
		return InstallerParentAccessEvidence{},ErrUnqualifiedInstallerParentAccess
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err:=p.verifyRetained();err!=nil {
		return InstallerParentAccessEvidence{},fmt.Errorf("%w: before AccessCheck identity: %v",ErrUnqualifiedInstallerParentAccess,err)
	}
	if impersonating,err:=isInstallerThreadImpersonating();err!=nil || impersonating {
		return InstallerParentAccessEvidence{},fmt.Errorf("%w: thread impersonation observed before AccessCheck: %v",ErrUnqualifiedInstallerParentAccess,err)
	}
	token,err:=inspectNativeInstallerProcessToken()
	if err!=nil{return InstallerParentAccessEvidence{},err}
	// OWNER/GROUP/DACL are required for Windows AccessCheck. No SACL read,
	// privilege enable, or named path lookup is performed.
	sd,err:=windows.GetSecurityInfo(p.programData.handle,windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err!=nil || sd==nil {
		return InstallerParentAccessEvidence{},fmt.Errorf("%w: retained ProgramData security descriptor: %v",ErrUnqualifiedInstallerParentAccess,err)
	}
	acl,err:=systemParentACLFromDescriptor(sd)
	if err!=nil{return InstallerParentAccessEvidence{},err}
	before:=sd.String()
	if before=="" {
		return InstallerParentAccessEvidence{},fmt.Errorf("%w: unable to retain exact ProgramData descriptor comparison",ErrUnqualifiedInstallerParentAccess)
	}
	checkToken,err:=nativeAccessCheckTokenFromProcess()
	if err!=nil{return InstallerParentAccessEvidence{},err}
	defer checkToken.Close()
	// Ensure both independently queried token handles still represent the
	// same process user. This is a read-only consistency check; it cannot
	// authenticate an operator or forbid a privileged actor changing tokens.
	user,err:=checkToken.GetTokenUser()
	if err!=nil || user==nil || user.User.Sid==nil ||
		user.User.Sid.String()!=token.UserSID {
		return InstallerParentAccessEvidence{},fmt.Errorf("%w: access-check token user differs from inspected process user: %v",ErrUnqualifiedInstallerParentAccess,err)
	}
	create,err:=nativeCheckInstallerRight(sd,checkToken,installerParentCreateChild)
	if err!=nil{return InstallerParentAccessEvidence{},err}
	read,err:=nativeCheckInstallerRight(sd,checkToken,installerParentReadControl)
	if err!=nil{return InstallerParentAccessEvidence{},err}
	after,err:=windows.GetSecurityInfo(p.programData.handle,windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err!=nil || after==nil || after.String()!=before {
		return InstallerParentAccessEvidence{},fmt.Errorf("%w: ProgramData owner/group/DACL changed during observation: %v",ErrUnqualifiedInstallerParentAccess,err)
	}
	if err:=p.verifyRetained();err!=nil {
		return InstallerParentAccessEvidence{},fmt.Errorf("%w: after AccessCheck identity: %v",ErrUnqualifiedInstallerParentAccess,err)
	}
	if impersonating,err:=isInstallerThreadImpersonating();err!=nil || impersonating {
		return InstallerParentAccessEvidence{},fmt.Errorf("%w: thread impersonation observed after AccessCheck: %v",ErrUnqualifiedInstallerParentAccess,err)
	}
	return InstallerParentAccessEvidence{
		Token:token,SystemParent:p.Evidence(),ProgramDataACL:acl,
		CreateChild:create,ReadControl:read,
	},nil
}
