// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import "time"

const serviceSecurityEmptyWindowGroupLimit = 64
const serviceSecurityBacklogMaximumDelay = time.Second

// nextServiceWindowsSecurityDelay bounds successive catch-up attempts without
// turning a continuously advancing Security log into a busy retry loop.
// When no checkpoint advanced, fall back to the normal configured cadence.
func nextServiceWindowsSecurityDelay(interval time.Duration, moreAvailable, checkpointAdvanced bool) time.Duration {
	if !moreAvailable || !checkpointAdvanced {
		return interval
	}
	if interval < serviceSecurityBacklogMaximumDelay {
		return interval
	}
	return serviceSecurityBacklogMaximumDelay
}

// shouldPublishServiceSecurityWindow groups windows without FI-selected events,
// including windows containing only out-of-scope Security query results.
// Selected events must be published immediately; the final window must flush
// a partial group before checkpoint advancement.
func shouldPublishServiceSecurityWindow(emptyWindows int, hasMatchingEvents, finalWindow bool) bool {
	return hasMatchingEvents || finalWindow || emptyWindows >= serviceSecurityEmptyWindowGroupLimit
}
