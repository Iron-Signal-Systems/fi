// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package objbroker

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/scopeidentity"
)

func TestAuthoritySnapshotUsesCapturedGovernedRoots(t *testing.T) {
	roots := []string{`C:\FI-Lab`}

	snapshot, err := newAuthoritySnapshot(roots)
	if err != nil {
		t.Fatal(err)
	}

	// Mutation of the caller's slice after startup must not change authority.
	roots[0] = `D:\Changed`

	resolved, ok := snapshot.resolveGovernedRoot(`c:\fi-lab\`)
	if !ok {
		t.Fatal("captured governed root was not authorized")
	}
	if resolved.GovernedRoot != `C:\FI-Lab` {
		t.Fatalf("configured root = %q, want %q", resolved.GovernedRoot, `C:\FI-Lab`)
	}
	wantScopeID := scopeidentity.GovernedRootScopeID(`C:\FI-Lab`)
	if resolved.ScopeID != wantScopeID {
		t.Fatalf("scope id = %q, want %q", resolved.ScopeID, wantScopeID)
	}

	if _, ok := snapshot.resolveGovernedRoot(`C:\Other`); ok {
		t.Fatal("unconfigured governed root was authorized")
	}
	if _, ok := snapshot.resolveGovernedRoot(`C:\FI-Lab\Child`); ok {
		t.Fatal("child path was accepted as a governed-root authority request")
	}
}

func TestAuthoritySnapshotRejectsEmptyConfiguration(t *testing.T) {
	if _, err := newAuthoritySnapshot(nil); err == nil {
		t.Fatal("expected empty governed-root configuration rejection")
	}
}
