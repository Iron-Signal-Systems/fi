// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnraw

import (
	"syscall"
	"testing"
)

func TestReadSACLRejectsFileReferenceAbove48Bits(t *testing.T) {
	_, err := ReadSACL(`C:\FI-Lab`, 1<<48, 2)
	if err == nil {
		t.Fatal("expected oversized file-reference rejection")
	}
}

func TestRestoreSACLPrivilegeRejectsInvalidToken(t *testing.T) {
	if err := restoreSACLPrivilege(saclPrivilegeScope{}); err == nil {
		t.Fatal("expected invalid privilege-scope token rejection")
	}
}

func TestSACLWindowsErrorCode(t *testing.T) {
	if got := saclWindowsErrorCode(syscall.Errno(1300)); got != 1300 {
		t.Fatalf("error code = %d, want 1300", got)
	}
	if got := saclWindowsErrorCode(nil); got != 0 {
		t.Fatalf("nil error code = %d, want 0", got)
	}
}
