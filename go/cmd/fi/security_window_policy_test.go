// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"testing"
	"time"
)

func TestNextServiceWindowsSecurityDelay(t *testing.T) {
	tests := []struct {
		name     string
		interval time.Duration
		more     bool
		advanced bool
		want     time.Duration
	}{
		{"normal cadence", time.Minute, false, true, time.Minute},
		{"no progress", time.Minute, true, false, time.Minute},
		{"progress and backlog", time.Minute, true, true, time.Second},
		{"short configured cadence", 20 * time.Millisecond, true, true, 20 * time.Millisecond},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := nextServiceWindowsSecurityDelay(tc.interval, tc.more, tc.advanced)
			if got != tc.want {
				t.Fatalf("delay = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestShouldPublishServiceSecurityWindow(t *testing.T) {
	tests := []struct {
		name    string
		empty   int
		matched bool
		final   bool
		publish bool
	}{
		{"defer first empty window", 1, false, false, false},
		{"defer bounded empty backlog", serviceSecurityEmptyWindowGroupLimit - 1, false, false, false},
		{"flush bounded empty backlog", serviceSecurityEmptyWindowGroupLimit, false, false, true},
		{"flush partial group at target", 4, false, true, true},
		{"publish events immediately", 10, true, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldPublishServiceSecurityWindow(tc.empty, tc.matched, tc.final)
			if got != tc.publish {
				t.Fatalf("publish = %t, want %t", got, tc.publish)
			}
		})
	}
}

func TestEmptySecurityWindowGroupingAccountsForEntireRange(t *testing.T) {
	const windows = 130
	empty := 0
	published := 0
	lastDurableWindow := 0

	for window := 1; window <= windows; window++ {
		empty++
		if empty > serviceSecurityEmptyWindowGroupLimit {
			t.Fatalf("unbounded pending windows: %d", empty)
		}
		if shouldPublishServiceSecurityWindow(empty, false, window == windows) {
			published++
			lastDurableWindow = window
			empty = 0
		}
	}

	if published != 3 || empty != 0 || lastDurableWindow != windows {
		t.Fatalf("publications=%d pending=%d durable_end=%d", published, empty, lastDurableWindow)
	}
}
