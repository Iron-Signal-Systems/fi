// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usnraw

import "testing"

func TestContainmentIsServer2025Version(t *testing.T) {
	for _, test := range []struct {
		name  string
		major uint32
		minor uint32
		build uint32
		want  bool
	}{
		{name: "server-2016", major: 10, minor: 0, build: 14393, want: false},
		{name: "server-2019", major: 10, minor: 0, build: 17763, want: false},
		{name: "server-2022", major: 10, minor: 0, build: 20348, want: false},
		{name: "server-2025", major: 10, minor: 0, build: 26100, want: true},
		{name: "server-2025-adjacent-build", major: 10, minor: 0, build: 26101, want: false},
		{name: "wrong-major", major: 11, minor: 0, build: 26100, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := containmentIsServer2025Version(
				test.major,
				test.minor,
				test.build,
			)
			if got != test.want {
				t.Fatalf(
					"containmentIsServer2025Version(%d, %d, %d) = %v, want %v",
					test.major,
					test.minor,
					test.build,
					got,
					test.want,
				)
			}
		})
	}
}
