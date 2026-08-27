// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package securityevent

import (
	"strings"
	"testing"
)

func TestReadSelectedEventsRejectsOversizedRangeBeforeWindowsQuery(t *testing.T) {
	_, err := ReadSelectedEvents(100, 100+MaxReadRecordIDSpan+1)
	if err == nil {
		t.Fatal("expected oversized EventRecordID range rejection")
	}
	if !strings.Contains(err.Error(), "exceeds bounded EventRecordID span") {
		t.Fatalf("error = %v", err)
	}
}

func TestReadSelectedEventsEmptyRangeDoesNotQueryWindows(t *testing.T) {
	events, err := ReadSelectedEvents(100, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("events = %d, want 0", len(events))
	}
}

func TestReadSelectedEventsReversedRangeDoesNotQueryWindows(t *testing.T) {
	events, err := ReadSelectedEvents(101, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("events = %d, want 0", len(events))
	}
}
