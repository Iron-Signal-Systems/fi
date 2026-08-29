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
