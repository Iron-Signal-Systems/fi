// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"testing"
	"time"
)

// TestRunServiceWindowsSecurityLoopDrainsAfterReinitialization guards against
// turning a recovered oldest-1 checkpoint into another one-minute idle wait.
// The fake source returns a recovered backlog, then a caught-up result.
func TestRunServiceWindowsSecurityLoopDrainsAfterReinitialization(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source := &fakeServiceWindowsSecuritySource{
		summaries: []serviceWindowsSecurityCycleSummary{
			{
				Status:                  configuredSecurityComplete,
				MoreAvailable:           true,
				CheckpointReinitialized: true,
			},
			{
				Status:        configuredSecurityComplete,
				MoreAvailable: false,
			},
		},
	}

	records := make(chan serviceRuntimeRecord, 2)
	done := make(chan error, 1)
	go func() {
		done <- runServiceWindowsSecurityLoop(ctx, time.Hour, source,
			func(record serviceRuntimeRecord) error {
				records <- record
				if calls, _ := source.snapshot(); calls == 2 {
					cancel()
				}
				return nil
			},
		)
	}()

	for index := 0; index < 2; index++ {
		select {
		case record := <-records:
			if record.RecordKind != "WindowsSecurityCatchUp" {
				t.Fatalf("record %d kind %q", index, record.RecordKind)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("recovery backlog waited for the normal hourly interval")
		}
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Security worker did not terminate after cancellation")
	}
	calls, concurrent := source.snapshot()
	if calls != 2 || concurrent != 1 {
		t.Fatalf("collector calls=%d overlap=%d, want 2 and 1", calls, concurrent)
	}
}
