// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/securityevent"
)

func TestSelectServiceWindowsSecurityEventsAllOutOfScope(t *testing.T) {
	const count = 725
	events := make([]records.WindowsSecurityEventObservation, count)
	for index := range events {
		events[index] = records.WindowsSecurityEventObservation{
			EventID: "4663", ObjectType: "File", ObjectName: `C:\Windows\Temp\unrelated.txt`,
		}
	}
	scopes := []securityevent.GovernedScope{{ScopeID: "governed", GovernedRoot: `G:\FI-M6-GOVERNED`}}
	selected, ignored := selectServiceWindowsSecurityEvents(events, scopes)
	if len(selected) != 0 || ignored != count {
		t.Fatalf("selected=%d ignored=%d, want 0 and %d", len(selected), ignored, count)
	}

	// The observed 27 windows must be represented by one publication,
	// not 27 coverage-only batches when every query event is out of scope.
	emptyWindows, publications := 0, 0
	for window := 1; window <= 27; window++ {
		emptyWindows++
		if shouldPublishServiceSecurityWindow(emptyWindows, len(selected) > 0, window == 27) {
			publications++
			emptyWindows = 0
		}
	}
	if publications != 1 || emptyWindows != 0 {
		t.Fatalf("publications=%d pending=%d, want 1 and 0", publications, emptyWindows)
	}
}

func TestSelectServiceWindowsSecurityEventsPreservesSelectedOrder(t *testing.T) {
	events := []records.WindowsSecurityEventObservation{
		{EventID: "4663", ObjectType: "File", ObjectName: `C:\Windows\Temp\not-governed.txt`},
		{EventID: "4663", ObjectType: "File", ObjectName: `G:\FI-M6-GOVERNED\included.txt`},
		{EventID: "4719"},
	}
	scopes := []securityevent.GovernedScope{{ScopeID: "governed", GovernedRoot: `G:\FI-M6-GOVERNED`}}
	selected, ignored := selectServiceWindowsSecurityEvents(events, scopes)
	if len(selected) != 2 || ignored != 1 {
		t.Fatalf("selected=%d ignored=%d, want 2 and 1", len(selected), ignored)
	}
	if selected[0].EventID != "4663" || selected[1].EventID != "4719" {
		t.Fatalf("selected order changed: %+v", selected)
	}
	if len(selected[0].MatchedScopes) != 1 || selected[0].MatchedScopes[0].ScopeID != "governed" {
		t.Fatalf("path-matched scope was lost: %+v", selected[0].MatchedScopes)
	}
	if selected[1].ScopeBasis != records.WindowsSecurityScopeHostMonitoringChange {
		t.Fatalf("host-monitoring event was lost: %q", selected[1].ScopeBasis)
	}
}
