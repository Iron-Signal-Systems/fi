// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"
)

func TestWindowsSACLAuditRights(t *testing.T) {
	if !fiSACLAuditFlags(fiSACLChangeMask, 0xC3, true) {
		t.Fatal("change coverage rejected")
	}
	if fiSACLAuditFlags(fiSACLChangeMask, 0xCB, true) {
		t.Fatal("inherit-only change wrongly accepted")
	}
	if !fiSACLAuditFlags(fiSACLReadMask, 0xC9, false) {
		t.Fatal("descendant read rejected")
	}
	if fiSACLAuditFlags(fiSACLReadMask, 0x89, false) {
		t.Fatal("read without success accepted")
	}
}
func TestWindowsSACLSDDLAppendPreservesPriorEntries(t *testing.T) {
	const old = "S:AR(AU;OICISAFA;0x2;;;SY)"
	next, err := fiSACLWithRequired(old, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(next, old) || !strings.Contains(next, fiChangeACE) || !strings.Contains(next, fiReadACE) {
		t.Fatal("existing SACL overwritten")
	}
	if _, err := fiSACLWithRequired("D:(A;;FA;;;SY)", true, false); err == nil {
		t.Fatal("non-SACL descriptor accepted")
	}
}
func TestWindowsSACLRootSetRejectsOverlap(t *testing.T) {
	if _, err := fiSACLRoots([]string{`C:\Shares`, `C:\Shares\Child`}); err == nil {
		t.Fatal("nested roots accepted")
	}
	roots, err := fiSACLRoots([]string{`D:\Data`, `C:\Data`, `c:\data`})
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) != 2 {
		t.Fatalf("roots=%v", roots)
	}
}
