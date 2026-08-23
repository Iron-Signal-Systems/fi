// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"syscall"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

// Server 2016 regression: FI must be able to collect a directory security
// descriptor through the production OpenFileById path. ReOpenFile(READ_CONTROL)
// was proven to fail with Access Denied for directory handles on the target
// Server 2016 environment.
func TestDirectorySecurityDescriptorOpenByID(t *testing.T) {
	path := t.TempDir()

	units, err := syscall.UTF16FromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := openPath(units)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)

	raw, err := querySecurityDescriptor(handle)
	if err != nil {
		t.Fatal(err)
	}

	observation, err := records.ParseSecurityDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := records.ValidateSecurityObservation(observation); err != nil {
		t.Fatal(err)
	}
	if observation.OwnerSID == "" {
		t.Fatal("expected owner SID")
	}
	if observation.DACL.State == "" {
		t.Fatal("expected DACL state")
	}
}

// Server 2016 regression: with SeSecurityPrivilege available, FI must be able
// to collect a directory SACL through the production OpenFileById path.
func TestDirectorySACLDescriptorOpenByID(t *testing.T) {
	if err := ensureSeSecurityPrivilege(); err != nil {
		t.Skipf("SeSecurityPrivilege unavailable: %v", err)
	}

	path := t.TempDir()

	units, err := syscall.UTF16FromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := openPath(units)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)

	raw, err := querySACLDescriptor(handle)
	if err != nil {
		t.Fatal(err)
	}

	observation, err := records.ParseSACLDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := records.ValidateSACLObservation(observation); err != nil {
		t.Fatal(err)
	}
}
