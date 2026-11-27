// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package auditpolicy

import "testing"

func TestRequiredPolicyContract(t *testing.T) {
	cases := map[string]uint32{
		"Audit Policy Change": Success,
		"File System":         Success | Failure,
		"Handle Manipulation": Failure,
		"Detailed File Share": Success | Failure,
	}
	r := Required()
	if len(r) != len(cases) {
		t.Fatalf("unexpected required count %d", len(r))
	}
	seen := make(map[string]bool)
	for _, p := range r {
		expected, ok := cases[p.ID]
		if !ok || seen[p.ID] || expected != p.Required || p.GUID == "" {
			t.Fatalf("unexpected audit-policy contract: %+v", p)
		}
		seen[p.ID] = true
		for current := uint32(0); current <= 3; current++ {
			updated := Desired(current, p.Required)
			if updated&current != current || !Sufficient(updated, p.Required) {
				t.Fatalf("policy update removed existing flags: %s old=%d new=%d", p.ID, current, updated)
			}
		}
	}
	r[0].Required = 0
	if Required()[0].Required == 0 {
		t.Fatal("caller mutated shared audit-policy contract")
	}
}
