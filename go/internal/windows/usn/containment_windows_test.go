// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"syscall"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

func TestIsOpenFileByIDAccessDenied(t *testing.T) {
	if !IsOpenFileByIDAccessDenied(&ntfs.Error{
		Stage: ntfs.StageOpen,
		Op:    "OpenFileById",
		Err:   syscall.ERROR_ACCESS_DENIED,
	}) {
		t.Fatal("expected OpenFileById access denied to match")
	}

	for _, err := range []error{
		&ntfs.Error{Stage: ntfs.StageMetadata, Op: "GetFileInformationByHandleEx", Err: syscall.ERROR_ACCESS_DENIED},
		&ntfs.Error{Stage: ntfs.StageOpen, Op: "CreateFileW", Err: syscall.ERROR_ACCESS_DENIED},
		&ntfs.Error{Stage: ntfs.StageOpen, Op: "OpenFileById", Err: syscall.ERROR_FILE_NOT_FOUND},
	} {
		if IsOpenFileByIDAccessDenied(err) {
			t.Fatalf("unexpected match for %v", err)
		}
	}
}
