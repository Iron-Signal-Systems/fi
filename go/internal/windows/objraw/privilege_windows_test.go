// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package objraw

import (
	"syscall"
	"testing"
)

func TestBackupWindowsErrorCode(t *testing.T) {
	if got := backupWindowsErrorCode(syscall.Errno(1300)); got != 1300 {
		t.Fatalf("Windows error code = %d, want 1300", got)
	}
	if got := backupWindowsErrorCode(nil); got != 0 {
		t.Fatalf("nil Windows error code = %d, want 0", got)
	}
}

func TestRestoreBackupPrivilegeRejectsInvalidToken(t *testing.T) {
	if err := restoreBackupPrivilege(backupPrivilegeScope{}); err == nil {
		t.Fatal("expected invalid-token restore failure")
	}
}
