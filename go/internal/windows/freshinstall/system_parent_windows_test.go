// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// This test is deliberately READ-ONLY on the GitHub runner's actual Windows
// installation. It never creates FI artifacts or changes Windows ACLs. It
// establishes API/object identity behavior, not trust of an install issuer.
func TestNativeSystemProgramDataEvidenceFromOSAndHandles(t *testing.T) {
	observed,err:=inspectNativeSystemProgramData()
	if err!=nil {t.Fatalf("read-only OS system-parent inspection: %v",err)}
	defer observed.Close()
	if err:=AssessSystemParentEvidence(observed.Evidence());err!=nil{
		t.Fatalf("native system parent evidence violated local policy: %v",err)
	}
	if err:=observed.verifyRetained();err!=nil {
		t.Fatalf("native root/windows/ProgramData changed during read-only inspection: %v",err)
	}
	win,err:=windows.GetSystemWindowsDirectory()
	if err!=nil {t.Fatal(err)}
	pd,err:=windows.KnownFolderPath(windows.FOLDERID_ProgramData,0)
	if err!=nil {t.Fatal(err)}
	if !sameNativePath(observed.Evidence().SystemWindows,win) ||
		!sameNativePath(observed.Evidence().KnownProgramData,pd) {
		t.Fatal("inspection did not use independent OS Windows and known-folder APIs")
	}
	// Root and both direct children must be different objects on the same
	// full-width volume serial, not merely share drive-letter strings.
	e:=observed.Evidence()
	if e.RootID.FileID==e.ProgramDataID.FileID ||
		e.ProgramDataID.FileID==e.WindowsID.FileID ||
		e.RootID.VolumeSerial!=e.WindowsID.VolumeSerial {
		t.Fatalf("observed native identities are not distinct: %+v",e)
	}
}

func TestNativeSystemProgramDataEvidenceRefusesTamperedIdentityAndClosedHandles(t *testing.T) {
	observed,err:=inspectNativeSystemProgramData()
	if err!=nil {t.Fatal(err)}
	defer observed.Close()
	original:=observed.programData.id
	observed.programData.id.FileID[15]^=0xFF
	if err:=observed.verifyRetained();!errors.Is(err,ErrUnattestedSystemParent){
		t.Fatalf("altered original FILE_ID_INFO accepted: %v",err)
	}
	observed.programData.id=original
	originalName:=observed.programData.nativePath
	observed.programData.nativePath=filepath.Join(filepath.Dir(originalName),"redirected")
	if err:=observed.verifyRetained();!errors.Is(err,ErrUnattestedSystemParent){
		t.Fatalf("altered original native path accepted: %v",err)
	}
	observed.programData.nativePath=originalName
	if err:=observed.verifyRetained();err!=nil{
		t.Fatalf("valid native identity not recoverable after test mutation: %v",err)
	}
	if err:=observed.Close();err!=nil{t.Fatal(err)}
	if err:=observed.verifyRetained();!errors.Is(err,ErrUnattestedSystemParent){
		t.Fatalf("released directory handles accepted as trustworthy: %v",err)
	}
}

// No test mutates the actual Windows ProgramData directory, so an actual
// namespace substitution attack and protected installer service tokens
// remain the controlled adminbox acceptance domain, not this CI fixture.
