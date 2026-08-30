// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnraw

import "testing"

func TestContainmentPathContainedBy(t *testing.T) {
	root := `\\?\Volume{11111111-1111-1111-1111-111111111111}\FI-Governed-Test`

	for _, test := range []struct {
		name   string
		target string
		want   bool
	}{
		{name: "root", target: root, want: true},
		{name: "child", target: root + `\Sub\file.txt`, want: true},
		{name: "case", target: `\\?\Volume{11111111-1111-1111-1111-111111111111}\fi-governed-test\Sub`, want: true},
		{name: "prefix-only", target: root + `-Other\file.txt`, want: false},
		{name: "outside", target: `\\?\Volume{11111111-1111-1111-1111-111111111111}\Windows\System32`, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := containmentPathContainedBy(root, test.target); got != test.want {
				t.Fatalf("contained = %v, want %v", got, test.want)
			}
		})
	}
}
