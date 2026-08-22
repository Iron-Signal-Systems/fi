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

func TestSecurityNativeSACLQuery(t *testing.T) {
	path := t.TempDir() + `\sacl.txt`
	if err := os.WriteFile(path, []byte("fi"), 0o600); err != nil {
		t.Fatal(err)
	}

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
		if code := saclQueryReasonCode(err); code == saclPrivilegeUnavailable {
			t.Logf("SACL query correctly reported unavailable privilege: %v", err)
			return
		}
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

func TestSACLQueryReasonCodeDefaultsToReadFailure(t *testing.T) {
	if got := saclQueryReasonCode(syscall.EINVAL); got != saclDescriptorReadFailed {
		t.Fatalf("reason code = %q", got)
	}
}
