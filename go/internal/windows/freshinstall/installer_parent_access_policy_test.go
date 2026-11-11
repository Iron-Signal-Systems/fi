// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package freshinstall

import (
	"errors"
	"testing"
)

func eligibleInstallerParentAccessFixture() InstallerParentAccessEvidence {
	return InstallerParentAccessEvidence{
		Token: allowedInstallerTokenEvidence(),
		SystemParent: testSystemEvidence(),
		ProgramDataACL: safeSystemParentACL(),
		CreateChild: InstallerParentRight{
			Requested:installerParentCreateChild,Completed:true,Allowed:true,
			Granted:installerParentCreateChild,
		},
		ReadControl: InstallerParentRight{
			Requested:installerParentReadControl,Completed:true,Allowed:true,
			Granted:installerParentReadControl,
		},
	}
}

func TestInstallerParentRightsPolicyRequiresAllIndependentEvidence(t *testing.T) {
	good:=eligibleInstallerParentAccessFixture()
	if err:=AssessInstallerParentAccess(good);err!=nil{t.Fatal(err)}
	for _,tc:=range []struct{
		name string
		change func(*InstallerParentAccessEvidence)
	}{
		{"token UAC limited",func(x *InstallerParentAccessEvidence){x.Token.ElevationType=3}},
		{"token not administrator",func(x *InstallerParentAccessEvidence){x.Token.AdministratorsEnabled=false}},
		{"wrong system volume",func(x *InstallerParentAccessEvidence){x.SystemParent.ProgramDataID.VolumeSerial++}},
		{"untrusted ProgramData ACL",func(x *InstallerParentAccessEvidence){x.ProgramDataACL.Entries[2].Mask|=installerParentCreateChild}},
		{"native create unknown",func(x *InstallerParentAccessEvidence){x.CreateChild.Completed=false}},
		{"native create denied",func(x *InstallerParentAccessEvidence){x.CreateChild.Allowed=false;x.CreateChild.Granted=0}},
		{"native read-control denied",func(x *InstallerParentAccessEvidence){x.ReadControl.Allowed=false;x.ReadControl.Granted=0}},
		{"wrong right requested",func(x *InstallerParentAccessEvidence){x.CreateChild.Requested=installerParentReadControl}},
		{"generic maximum allowed",func(x *InstallerParentAccessEvidence){x.CreateChild.Requested=0x02000000}},
		{"privilege-mediated create",func(x *InstallerParentAccessEvidence){x.CreateChild.PrivilegesUsed=1}},
		{"privilege-mediated read",func(x *InstallerParentAccessEvidence){x.ReadControl.PrivilegesUsed=1}},
		{"granted mask inconsistent",func(x *InstallerParentAccessEvidence){x.CreateChild.Granted=installerParentReadControl}},
		{"granted extra rights",func(x *InstallerParentAccessEvidence){x.CreateChild.Granted|=installerParentReadControl}},
		{"native requested bits invalid",func(x *InstallerParentAccessEvidence){x.CreateChild.Requested=0}},
	} {
		t.Run(tc.name,func(t *testing.T) {
			x:=eligibleInstallerParentAccessFixture()
			tc.change(&x)
			if err:=AssessInstallerParentAccess(x);!errors.Is(err,ErrUnqualifiedInstallerParentAccess){
				t.Fatalf("invalid parent access evidence accepted: err=%v",err)
			}
		})
	}
}

func TestInstallerParentRightsNativeDenialIsNotMissingEvidence(t *testing.T) {
	x:=eligibleInstallerParentAccessFixture()
	x.CreateChild.Allowed=false
	x.CreateChild.Granted=0
	if err:=validateInstallerParentRight(x.CreateChild,installerParentCreateChild);!errors.Is(err,ErrUnqualifiedInstallerParentAccess){
		t.Fatalf("explicit native access denial accepted: %v",err)
	}
}
