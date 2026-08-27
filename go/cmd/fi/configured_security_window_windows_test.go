// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/securityevent"
)

func TestNextConfiguredSecurityWindowEndUsesBoundedSpan(t *testing.T) {
	start := uint64(100)
	target := start + securityevent.MaxReadRecordIDSpan + 25
	got := nextConfiguredSecurityWindowEnd(start, target)
	want := start + securityevent.MaxReadRecordIDSpan
	if got != want {
		t.Fatalf("window end = %d, want %d", got, want)
	}
}

func TestNextConfiguredSecurityWindowEndUsesShortFinalWindow(t *testing.T) {
	start := uint64(100)
	target := start + 25
	if got := nextConfiguredSecurityWindowEnd(start, target); got != target {
		t.Fatalf("window end = %d, want %d", got, target)
	}
}

func TestNextConfiguredSecurityWindowEndDoesNotAdvancePastTarget(t *testing.T) {
	if got := nextConfiguredSecurityWindowEnd(100, 100); got != 100 {
		t.Fatalf("window end = %d, want 100", got)
	}
	if got := nextConfiguredSecurityWindowEnd(101, 100); got != 100 {
		t.Fatalf("window end = %d, want 100", got)
	}
}
