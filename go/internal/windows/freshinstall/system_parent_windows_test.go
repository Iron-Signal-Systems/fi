// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package freshinstall

import (
	"errors"
	"path/filepath"
	"os"
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

func TestReadOnlyDirectoryAttestationRejectsNativeRenameAndReplacement(t *testing.T) {
	// This is an ISOLATED Windows runner fixture. It purposefully permits
	// delete-sharing on the original handle so the file can be renamed
	// while we hold it; this must never authorize a fresh path as the old
	// FILE_ID_INFO. Production observations use the stricter share mode.
	root:=t.TempDir()
	original:=filepath.Join(root,"original")
	moved:=filepath.Join(root,"moved")
	if err:=os.Mkdir(original,0700);err!=nil{t.Fatal(err)}
	obs,err:=openNativeSystemDirectoryWithSharing(original,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if err!=nil{t.Fatal(err)}
	defer windows.CloseHandle(obs.handle)
	if err:=verifyObservedSystemDirectory(obs);err!=nil{
		t.Fatalf("original read-only identity not stable: %v",err)
	}
	if err:=os.Rename(original,moved);err!=nil{
		t.Fatalf("cannot test actual Windows rename while keeping original native handle: %v",err)
	}
	// A path may be reused by a different object after the original has
	// been relocated. Its owner/ACL/volume alone would not establish
	// continuity; file identity must be compared with the retained handle.
	if err:=os.Mkdir(original,0700);err!=nil{t.Fatal(err)}
	replacement,err:=openNativeSystemDirectory(original)
	if err!=nil{t.Fatal(err)}
	if replacement.id==obs.id {
		_ = windows.CloseHandle(replacement.handle)
		t.Fatal("replacement unexpectedly reused the original full-width FileID")
	}
	if err:=windows.CloseHandle(replacement.handle);err!=nil{t.Fatal(err)}
	if err:=verifyObservedSystemDirectory(obs);!errors.Is(err,ErrUnattestedSystemParent){
		t.Fatalf("replaced original path passed retained native identity check: %v",err)
	}
}

// No test mutates the actual Windows ProgramData directory, so an actual
// namespace substitution attack and protected installer service tokens
// remain the controlled adminbox acceptance domain, not this CI fixture.
