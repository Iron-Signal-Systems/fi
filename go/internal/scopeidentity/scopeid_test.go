// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package scopeidentity

import "testing"

func TestGovernedRootScopeIDCanonicalizesCaseAndTrailingSlash(t *testing.T) {
	want := "root-4d0b32e74f10a1c3b023b428e67855df"

	for _, value := range []string{
		`C:\FI-Lab`,
		`c:\fi-lab\`,
		` C:\FI-Lab\ `,
	} {
		if got := GovernedRootScopeID(value); got != want {
			t.Fatalf("GovernedRootScopeID(%q) = %q, want %q", value, got, want)
		}
	}
}

func TestGovernedRootScopeIDKeepsDifferentRootsDistinct(t *testing.T) {
	left := GovernedRootScopeID(`C:\FI-Lab`)
	right := GovernedRootScopeID(`C:\FI-Other`)
	if left == right {
		t.Fatalf("different governed roots produced the same scope id %q", left)
	}
}
