// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import "testing"

func TestKeeperCLIRejectsMissingAuthority(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("keeper started with missing authority")
	}
}

func TestKeeperCLIRejectsDuplicateSource(t *testing.T) {
	var sources enrolledSourceFlags
	if err := sources.Set("iss-fs-22.iss.local"); err != nil {
		t.Fatal(err)
	}
	if err := sources.Set("iss-fs-22.iss.local"); err == nil {
		t.Fatal("duplicate enrolled source accepted")
	}
	if err := sources.Set("../../escape"); err == nil {
		t.Fatal("traversal source accepted")
	}
}
