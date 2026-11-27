// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestServiceWindowsSecuritySummaryPreservesCoverage(t *testing.T) {
	complete := configuredSecuritySummary{
		Status:   configuredSecurityComplete,
		Coverage: &records.WindowsSecurityCoverageObservation{Status: records.WindowsSecurityCoverageReady},
	}
	if got := summarizeServiceWindowsSecurity(complete, false).CoverageStatus; got != records.WindowsSecurityCoverageReady {
		t.Fatalf("Ready not propagated: %q", got)
	}
	complete.Coverage.Status = records.WindowsSecurityCoveragePartial
	if got := summarizeServiceWindowsSecurity(complete, false).CoverageStatus; got != records.WindowsSecurityCoveragePartial {
		t.Fatalf("Partial not propagated: %q", got)
	}
	complete.Coverage = nil
	if got := summarizeServiceWindowsSecurity(complete, false).CoverageStatus; got != "" {
		t.Fatalf("missing coverage falsely reported Ready: %q", got)
	}
}

func TestServiceWindowsSecurityRuntimeCarriesCoverageStatus(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &fakeServiceWindowsSecuritySource{
		summaries: []serviceWindowsSecurityCycleSummary{{
			Status:         configuredSecurityComplete,
			CoverageStatus: records.WindowsSecurityCoverageReady,
		}},
	}
	recordChannel := make(chan serviceRuntimeRecord, 1)
	done := make(chan error, 1)
	go func() {
		done <- runServiceWindowsSecurityLoop(ctx, time.Hour, source, func(record serviceRuntimeRecord) error {
			recordChannel <- record
			cancel()
			return nil
		})
	}()
	select {
	case record := <-recordChannel:
		if record.Outcome != "Complete" || record.SecurityCoverageStatus != "Ready" {
			t.Fatalf("runtime record lost Ready status: %+v", record)
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(encoded), `"security_coverage_status":"Ready"`) {
			t.Fatalf("persisted runtime JSON does not include Ready: %s", encoded)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Security runtime record was not written")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Security worker did not stop")
	}
}
