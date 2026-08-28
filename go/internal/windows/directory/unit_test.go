// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package directory

import (
	"encoding/hex"
	"testing"
)

func TestSIDStringToBytes(t *testing.T) {
	raw, err := sidStringToBytes("S-1-5-21-1-2-3-1106")
	if err != nil {
		t.Fatalf("sidStringToBytes: %v", err)
	}
	got := hex.EncodeToString(raw)
	want := "01050000000000051500000001000000020000000300000052040000"
	if got != want {
		t.Fatalf("raw SID = %s, want %s", got, want)
	}
}

func TestLDAPSIDFilterValue(t *testing.T) {
	raw := []byte{0x01, 0x05, 0x00, 0xff}
	if got, want := ldapSIDFilterValue(raw), `\01\05\00\ff`; got != want {
		t.Fatalf("filter = %q, want %q", got, want)
	}
}

func TestSortedUnique(t *testing.T) {
	got := sortedUnique([]string{"b", "a", "b", "", "c"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSIDBytesToString(t *testing.T) {
	raw, err := hex.DecodeString("01050000000000051500000001000000020000000300000052040000")
	if err != nil {
		t.Fatal(err)
	}
	got, err := sidBytesToString(raw)
	if err != nil {
		t.Fatalf("sidBytesToString: %v", err)
	}
	if got != "S-1-5-21-1-2-3-1106" {
		t.Fatalf("SID = %q", got)
	}
}
