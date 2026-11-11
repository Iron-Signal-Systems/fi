// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/windows"
)

// This fixture checks the REAL Windows AccessCheck engine against
// ephemeral in-memory ACLs for the actual CI process user. No file, ACL,
// privilege, service, FI directory or thread token is ever changed.
func TestNativeAccessCheckAllowsAndDeniesExactProcessUserRights(t *testing.T) {
	e,err:=inspectNativeInstallerProcessToken()
	if err!=nil {t.Fatal(err)}
	checkToken,err:=nativeAccessCheckTokenFromProcess()
	if err!=nil {t.Fatal(err)}
	defer checkToken.Close()
	for _,tc:=range []struct{
		name string
		descriptor string
		wantCreate bool
		wantRead bool
	}{
		{
			name:"exact user create and read",
			descriptor:fmt.Sprintf("O:SYG:SYD:P(A;;0x00020004;;;%s)",e.UserSID),
			wantCreate:true,wantRead:true,
		},
		{
			name:"explicit deny create, allow read",
			descriptor:fmt.Sprintf("O:SYG:SYD:P(D;;0x00000004;;;%s)(A;;0x00020004;;;%s)",e.UserSID,e.UserSID),
			wantCreate:false,wantRead:true,
		},
		{
			name:"no user create or read ACE",
			descriptor:"O:SYG:SYD:P(A;;FA;;;SY)",
			wantCreate:false,wantRead:false,
		},
	} {
		t.Run(tc.name,func(t *testing.T) {
			sd,err:=windows.SecurityDescriptorFromString(tc.descriptor)
			if err!=nil {t.Fatalf("native SDDL fixture invalid: %v",err)}
			create,err:=nativeCheckInstallerRight(sd,checkToken,installerParentCreateChild)
			if err!=nil {t.Fatalf("Windows AccessCheck(create) failed: %v",err)}
			if !create.Completed || create.Allowed!=tc.wantCreate ||
				create.PrivilegesUsed!=0 {
				t.Fatalf("incorrect native create decision: %+v wantAllowed=%t",create,tc.wantCreate)
			}
			read,err:=nativeCheckInstallerRight(sd,checkToken,installerParentReadControl)
			if err!=nil {t.Fatalf("Windows AccessCheck(read) failed: %v",err)}
			if !read.Completed || read.Allowed!=tc.wantRead ||
				read.PrivilegesUsed!=0 {
				t.Fatalf("incorrect native read decision: %+v wantAllowed=%t",read,tc.wantRead)
			}
		})
	}
}

func TestNativeAccessCheckRejectsInvalidTokenAndUnknownRight(t *testing.T) {
	sd,err:=windows.SecurityDescriptorFromString("O:SYG:SYD:P(A;;FA;;;SY)")
	if err!=nil {t.Fatal(err)}
	token,err:=nativeAccessCheckTokenFromProcess()
	if err!=nil {t.Fatal(err)}
	defer token.Close()
	for _,tt:=range []struct {
		name string
		sd *windows.SECURITY_DESCRIPTOR
		token windows.Token
		right uint32
	}{
		{"nil descriptor",nil,token,installerParentCreateChild},
		{"invalid token",sd,windows.Token(windows.InvalidHandle),installerParentCreateChild},
		{"no token",sd,0,installerParentReadControl},
		{"MAXIMUM_ALLOWED",sd,token,0x02000000},
		{"GENERIC_ALL",sd,token,0x10000000},
		{"unknown mutation",sd,token,0x00040000},
		{"zero",sd,token,0},
	} {
		t.Run(tt.name,func(t *testing.T) {
			if _,err:=nativeCheckInstallerRight(tt.sd,tt.token,tt.right);!errors.Is(err,ErrUnqualifiedInstallerParentAccess) {
				t.Fatalf("invalid AccessCheck arguments accepted: %v",err)
			}
		})
	}
}

func TestNativeWindowsProgramDataEffectiveAccessObservationIsReadOnly(t *testing.T) {
	inspection,err:=inspectNativeSystemProgramData()
	if err!=nil {t.Fatalf("open read-only OS system directory handles: %v",err)}
	defer inspection.Close()
	actual,err:=inspection.inspectInstallerProgramDataAccess()
	if err!=nil {
		// A real host can expose unsupported ACL entries, missing privileges
		// or an unsupported token path. These remain blockers, NOT a CI
		// assertion that a development machine is installation-qualified.
		if !errors.Is(err,ErrUnsafeSystemParentACL) &&
			!errors.Is(err,ErrUnqualifiedInstallerParentAccess) &&
			!errors.Is(err,ErrUnqualifiedInstallerToken) {
			t.Fatalf("native access returned an unclassified error: %v",err)
		}
		t.Logf("read-only native ProgramData effective access observation BLOCKED: %v",err)
		return
	}
	if !actual.CreateChild.Completed || !actual.ReadControl.Completed ||
		actual.CreateChild.Requested!=installerParentCreateChild ||
		actual.ReadControl.Requested!=installerParentReadControl {
		t.Fatalf("native ProgramData access observation is incomplete")
	}
	verdict:=AssessInstallerParentAccess(actual)
	if verdict!=nil && !errors.Is(verdict,ErrUnqualifiedInstallerParentAccess) {
		t.Fatalf("native access policy returned unclassified error: %v",verdict)
	}
	t.Logf("native read-only ProgramData rights: create=%t read-control=%t policy=%v",
		actual.CreateChild.Allowed,actual.ReadControl.Allowed,verdict)
}
