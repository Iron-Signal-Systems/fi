// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnraw

import "testing"

func TestDriveForRoot(t *testing.T) {
	for input, want := range map[string]string{
		`C:\Data`:     "C",
		`c:\Data`:     "C",
		`\\?\D:\Data`: "D",
	} {
		got, err := DriveForRoot(input)
		if err != nil {
			t.Fatalf("DriveForRoot(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("DriveForRoot(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestDriveForRootRejectsUNC(t *testing.T) {
	if _, err := DriveForRoot(`\\server\share\data`); err == nil {
		t.Fatal("expected UNC root rejection")
	}
}

func TestIsDriveRootMountPoint(t *testing.T) {
	for _, test := range []struct {
		name       string
		drive      string
		mountPoint string
		want       bool
	}{
		{name: "drive-root", drive: "C", mountPoint: `C:\`, want: true},
		{name: "drive-root-lowercase", drive: "c", mountPoint: `c:\`, want: true},
		{name: "extended-drive-root", drive: "D", mountPoint: `\\?\D:\`, want: true},
		{name: "directory-mounted-volume", drive: "C", mountPoint: `C:\County\MountedData\`, want: false},
		{name: "different-drive", drive: "C", mountPoint: `D:\`, want: false},
		{name: "different-extended-drive", drive: "C", mountPoint: `\\?\D:\`, want: false},
		{name: "invalid-drive", drive: "CC", mountPoint: `C:\`, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := isDriveRootMountPoint(test.drive, test.mountPoint)
			if got != test.want {
				t.Fatalf(
					"isDriveRootMountPoint(%q, %q) = %v, want %v",
					test.drive,
					test.mountPoint,
					got,
					test.want,
				)
			}
		})
	}
}

func TestValidateGovernedRootVolumeAcceptsOrdinaryDriveRoot(t *testing.T) {
	root := t.TempDir()

	drive, err := DriveForRoot(root)
	if err != nil {
		t.Fatalf("DriveForRoot(%q): %v", root, err)
	}
	if err := validateGovernedRootVolume(root, drive); err != nil {
		t.Fatalf("validateGovernedRootVolume(%q, %q): %v", root, drive, err)
	}
}
