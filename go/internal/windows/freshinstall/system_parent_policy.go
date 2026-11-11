// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package freshinstall contains development-only preflight contracts.
// The system parent evidence checks in this file are READ-ONLY consistency
// tests, not authentication of a Windows installation, operator or signer.
package freshinstall

import (
	"errors"
	"fmt"
	"strings"
)

var ErrUnattestedSystemParent = errors.New("FI v2 bootstrap system ProgramData parent cannot be attested")

// SystemDirectoryID is an observed full-width NTFS FILE_ID_INFO tuple.
// Neither path strings nor a matching volume serial alone identify a
// directory. FileID is an opaque 128-bit ID and must not be truncated.
type SystemDirectoryID struct {
	VolumeSerial uint64
	FileID [16]byte
}

// SystemParentEvidence is collected independently from native, read-only
// OS known-folder and Windows-directory APIs and three opened directory
// handles. It is NOT a signed grant, attestation by the OS's issuer, or a
// persisted installation commitment.
type SystemParentEvidence struct {
	KnownProgramData string
	SystemWindows string
	RootPath string
	RootID SystemDirectoryID
	ProgramDataID SystemDirectoryID
	WindowsID SystemDirectoryID
}

func validSystemPath(s string) bool {
	// This deliberately only admits plain absolute Win32 drive paths. A
	// native device path, UNC path, root alias, relative path, slash variant,
	// dot component or alternate data stream cannot be an install origin.
	if len(s)<3 || len(s)>1024 || !((s[0]>='A'&&s[0]<='Z')||(s[0]>='a'&&s[0]<='z')) ||
		s[1]!=':' || s[2]!='\\' || strings.ContainsAny(s,"/\x00") {
		return false
	}
	if len(s)==3 {return true}
	if s[len(s)-1]=='\\' {return false}
	for _,part:=range strings.Split(s[3:],"\\") {
		if part=="" || part=="." || part==".." ||
			strings.HasSuffix(part,".") || strings.HasSuffix(part," ") ||
			strings.ContainsAny(part,":*?\"<>|") {
			return false
		}
	}
	return true
}

func validDirectoryID(id SystemDirectoryID) bool {
	return id.VolumeSerial!=0 && id.FileID!=([16]byte{})
}

// validateSystemParentLayout checks the three OS-reported path shapes
// BEFORE any directory handles are opened. It cannot validate filesystem
// identity or be used alone to authorize a later mutation.
func validateSystemParentLayout(programData,systemWindows,root string) error {
	if !validSystemPath(root) || !validSystemPath(programData) ||
		!validSystemPath(systemWindows) ||
		len(root)!=3 || !strings.EqualFold(programData[:3],root) ||
		!strings.EqualFold(systemWindows[:3],root) ||
		!strings.EqualFold(programData[3:],"ProgramData") ||
		strings.Contains(systemWindows[3:],"\\") || systemWindows[3:]=="" ||
		strings.EqualFold(systemWindows,programData) {
		return fmt.Errorf("%w: ProgramData and system Windows must be distinct plain direct children of the same local system root", ErrUnattestedSystemParent)
	}
	return nil
}

// AssessSystemParentEvidence returns an error ONLY: it never bestows any
// mutation permission. The ProgramData OS known-folder must be a direct
// child named ProgramData of the same volume root as the shared Windows
// directory; the three independent full-width FILE_ID_INFO identities must
// be nonzero, distinct, and on the same NTFS volume.
//
// This intentionally refuses redirected ProgramData and nonstandard system
// layouts until they have a separately designed, explicitly authorized
// installation policy; a Windows known-folder path is not a trust issuer.
func AssessSystemParentEvidence(e SystemParentEvidence) error {
	if err:=validateSystemParentLayout(e.KnownProgramData,e.SystemWindows,e.RootPath);err!=nil {
		return err
	}
	if !validDirectoryID(e.RootID) || !validDirectoryID(e.ProgramDataID) ||
		!validDirectoryID(e.WindowsID) ||
		e.RootID.VolumeSerial!=e.ProgramDataID.VolumeSerial ||
		e.RootID.VolumeSerial!=e.WindowsID.VolumeSerial ||
		e.RootID.FileID==e.ProgramDataID.FileID ||
		e.RootID.FileID==e.WindowsID.FileID ||
		e.ProgramDataID.FileID==e.WindowsID.FileID {
		return fmt.Errorf("%w: missing, cross-volume or aliased full-width native FILE_ID_INFO", ErrUnattestedSystemParent)
	}
	return nil
}
