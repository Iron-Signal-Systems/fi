// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import "testing"

func TestConfiguredScopeIDEquivalentWindowsRoots(t *testing.T) {
	left := configuredScopeID(`D:\Shares\Finance`)
	right := configuredScopeID(`d:\shares\finance\`)
	if left != right {
		t.Fatalf("equivalent roots produced different scope IDs: %q != %q", left, right)
	}
}

func TestConfiguredScopeIDStableValue(t *testing.T) {
	const want = "root-1940386f154d3646c73ddbc054e4555a"
	if got := configuredScopeID(`D:\Shares\Finance`); got != want {
		t.Fatalf("scope ID = %q, want %q", got, want)
	}
}

func TestConfiguredScopeIDDifferentRoots(t *testing.T) {
	finance := configuredScopeID(`D:\Shares\Finance`)
	hr := configuredScopeID(`D:\Shares\HR`)
	if finance == hr {
		t.Fatalf("different roots produced same scope ID: %q", finance)
	}
}

func TestCompareUSN(t *testing.T) {
	tests := []struct {
		name  string
		left  string
		right string
		want  int
	}{
		{name: "less", left: "100", right: "101", want: -1},
		{name: "equal", left: "101", right: "101", want: 0},
		{name: "greater", left: "102", right: "101", want: 1},
		{name: "large", left: "9223372036854710272", right: "718844848", want: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := compareUSN(test.left, test.right)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("compareUSN(%q, %q) = %d, want %d", test.left, test.right, got, test.want)
			}
		})
	}
}

func TestCompareUSNRejectsMalformedValue(t *testing.T) {
	if _, err := compareUSN("not-a-usn", "1"); err == nil {
		t.Fatal("expected malformed USN error")
	}
}
