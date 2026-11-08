// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnraw

import (
	"errors"
	"strings"
	"testing"
)

const volumeTestGUID = `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`

func TestEnrolledVolumeNativeTargetRequiresExactGUIDAndSerial(t *testing.T) {
	raw, serial, err := enrolledVolumeDevicePath(volumeTestGUID, "15172277115761558407")
	if err != nil || raw != `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}` || serial != 15172277115761558407 {
		t.Fatalf("untrusted raw volume conversion: %q %d %v", raw, serial, err)
	}
}

func TestEnrolledVolumeNativeTargetRejectsUnsafeInputs(t *testing.T) {
	for _, tc := range []struct{ guid, serial string }{
		{`\\.\C:`, "15172277115761558407"},
		{`\\.\PhysicalDrive0`, "15172277115761558407"},
		{`C:\`, "15172277115761558407"},
		{`\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\subdir`, "15172277115761558407"},
		{`\\?\Volume{18fed846-4275-4251-b698-f268192100f2}`, "15172277115761558407"},
		{`\\?\Volume{zzfed846-4275-4251-b698-f268192100f2}\`, "15172277115761558407"},
		{volumeTestGUID, ""},
		{volumeTestGUID, "0"},
		{volumeTestGUID, "01"},
		{volumeTestGUID, "-1"},
		{volumeTestGUID, " 15172277115761558407"},
		{volumeTestGUID, "18446744073709551616"},
		{volumeTestGUID, "2;0"},
	} {
		if raw, _, err := enrolledVolumeDevicePath(tc.guid, tc.serial); err == nil {
			t.Fatalf("unsafe source accepted as raw volume target: %q (%q)", raw, tc.serial)
		}
	}
}

func TestEnrolledVolumeRejectsInvalidInputWithoutPrivilege(t *testing.T) {
	if _, err := QueryEnrolledVolume(`\\.\C:`, "1234"); err == nil {
		t.Fatal("raw arbitrary device path was not rejected")
	}
	if _, _, err := ReadEnrolledVolume(volumeTestGUID, "1234", -1); err == nil {
		t.Fatal("negative USN cursor accepted")
	}
	if _, _, err := ReadEnrolledVolume(volumeTestGUID, strings.Repeat("9", 100), 1); err == nil {
		t.Fatal("overflow serial accepted")
	}
}

func TestVolumeIdentityErrorIsDistinctFromTransientNativeError(t *testing.T) {
	if errors.Is(errors.New("access denied"), errEnrolledVolumeIdentity) {
		t.Fatal("transient volume error mislabeled as changed identity")
	}
	if !errors.Is(errEnrolledVolumeIdentity, errEnrolledVolumeIdentity) {
		t.Fatal("lost identity mismatch sentinel")
	}
}

// Native privileged raw-volume open and FSCTL tests MUST be run on adminbox
// under FIUSNReader's intended identity. The ordinary GitHub Windows runner
// cannot establish acceptance of the on-handle FileIdInfo contract, especially
// on Windows Server 2016/2019/2022/2025 and letterless/mounted volumes.
