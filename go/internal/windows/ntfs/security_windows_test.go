// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package ntfs

import (
	"os"
	"syscall"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestQuerySecurityDescriptorFromExistingHandle(t *testing.T) {
	file, err := os.CreateTemp("", "fi-security-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	path := file.Name()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)

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
