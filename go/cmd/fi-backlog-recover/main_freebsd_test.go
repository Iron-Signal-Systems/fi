//go:build freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package main

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

func TestPrivateWindowProfileLimits(t *testing.T) {
	tests := []struct {
		name string
		want recordingest.BacklogWindowLimits
	}{
		{"W32", recordingest.BacklogWindowLimits{MaxRecords: 32768, MaxDataBytes: 256 << 20}},
		{"W64", recordingest.BacklogWindowLimits{MaxRecords: 65536, MaxDataBytes: 1 << 30}},
		{"W96", recordingest.BacklogWindowLimits{MaxRecords: 98304, MaxDataBytes: 1 << 30}},
		{"W128", recordingest.BacklogWindowLimits{MaxRecords: 131072, MaxDataBytes: 1 << 30}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := privateWindowLimits(tc.name)
			if err != nil || got != tc.want {
				t.Fatalf("limits got=%+v want=%+v err=%v", got, tc.want, err)
			}
		})
	}
	for _, name := range []string{"", "W8", "W256", "W128K"} {
		if _, err := privateWindowLimits(name); err == nil {
			t.Fatalf("unexpected window profile %q accepted", name)
		}
	}
}

func TestExperimentalWindowModesFailClosed(t *testing.T) {
	for _, profile := range []string{"W64", "W96", "W128"} {
		if err := validatePrivateWindowMode(profile, true, true, false, false, false, 0, 1); err != nil {
			t.Fatalf("%s new isolated first window: %v", profile, err)
		}
		if err := validatePrivateWindowMode(profile, true, false, true, false, false, 1, 0); err != nil {
			t.Fatalf("%s continuous resume: %v", profile, err)
		}
		for _, tc := range []struct {
			name                      string
			enable, stream, continuous bool
			indexed, preflight        bool
			start, windows            int
		}{
			{name: "no writes", stream: true, start: 0, windows: 1},
			{name: "indexed forbidden", enable: true, stream: true, indexed: true, windows: 1},
			{name: "preflight forbidden", enable: true, stream: true, preflight: true, windows: 1},
			{name: "no batch selection", enable: true, start: 0, windows: 1},
			{name: "wrong first index", enable: true, stream: true, start: 1, windows: 1},
			{name: "two initial windows", enable: true, stream: true, start: 0, windows: 2},
			{name: "zero resume", enable: true, continuous: true, start: 0, windows: 0},
			{name: "bounded resume", enable: true, continuous: true, start: 1, windows: 1},
			{name: "mixed loaders", enable: true, stream: true, continuous: true, start: 1},
		} {
			if err := validatePrivateWindowMode(profile, tc.enable, tc.stream, tc.continuous,
				tc.indexed, tc.preflight, tc.start, tc.windows); err == nil {
				t.Errorf("%s accepted invalid %s mode", profile, tc.name)
			}
		}
	}
	// Preserve the legacy W32 modes used by the active recovery.
	if err := validatePrivateWindowMode("W32", false, false, false, false, false, 0, 0); err != nil {
		t.Fatalf("changed W32 behavior: %v", err)
	}
}
