// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package auditpolicy

import "testing"

func TestFIEventSelectionContract(t *testing.T) {
	expected := []uint32{1102, 4656, 4660, 4663, 4664, 4670, 4719, 4907, 5145}
	got := SelectedEventIDs()
	if len(got) != len(expected) {
		t.Fatalf("event contract length=%d", len(got))
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("event[%d]=%d want %d", i, got[i], expected[i])
		}
	}
	got[0] = 0
	if SelectedEventIDs()[0] == 0 {
		t.Fatal("event contract permits caller modification")
	}
	if ChangeAccessMask != 0xD0156 || DescendantReadMask != 1 || ChangeACEFlags != 0xC3 || DescendantReadACEFlags != 0xC9 {
		t.Fatal("audit SACL contract changed")
	}
}
