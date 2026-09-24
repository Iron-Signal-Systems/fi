// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnbroker

import "testing"

func TestAuthoritySnapshotUsesCapturedGovernedRoots(t *testing.T) {
	roots := []string{`C:\FI-Lab`}

	snapshot, err := newAuthoritySnapshot(roots)
	if err != nil {
		t.Fatal(err)
	}

	// Mutation of the caller's slice after startup must not change authority.
	roots[0] = `D:\Changed`

	if !snapshot.allowsGovernedRoot(`c:\fi-lab\`) {
		t.Fatal("captured governed root was not authorized")
	}
	if snapshot.allowsGovernedRoot(`C:\Other`) {
		t.Fatal("unconfigured governed root was authorized")
	}

	allowed, err := snapshot.allowsVolume(`C:\Other`)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Fatal("configured governed-root volume was not authorized")
	}

	allowed, err = snapshot.allowsVolume(`D:\Other`)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("unconfigured volume was authorized")
	}
}
