// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package process

import "testing"

func TestCurrentProcessResourceSnapshot(t *testing.T) {
	snapshot, err := Current()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.WorkingSetBytes == 0 {
		t.Fatal("working set is zero")
	}
	if snapshot.PeakWorkingSetBytes < snapshot.WorkingSetBytes {
		t.Fatalf("peak working set %d is less than current working set %d", snapshot.PeakWorkingSetBytes, snapshot.WorkingSetBytes)
	}
}

func TestWindowsVersion(t *testing.T) {
	version, err := WindowsVersion()
	if err != nil {
		t.Fatal(err)
	}
	if version == "" {
		t.Fatal("Windows version is empty")
	}
}
