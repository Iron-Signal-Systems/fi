// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/securityevent"
)

// selectServiceWindowsSecurityEvents performs the governed-scope selection
// before deciding whether the source query requires an immediate publication.
// The input is bounded to one 10,000-EventRecordID query window. Retain the
// selected order for durable append and count every out-of-scope source event.
func selectServiceWindowsSecurityEvents(
	events []records.WindowsSecurityEventObservation,
	scopes []securityevent.GovernedScope,
) ([]records.WindowsSecurityEventObservation, int) {
	selected := make([]records.WindowsSecurityEventObservation, 0, len(events))
	ignored := 0

	for _, event := range events {
		value, keep := securityevent.SelectEvent(event, scopes)
		if !keep {
			ignored++
			continue
		}
		selected = append(selected, value)
	}
	return selected, ignored
}
