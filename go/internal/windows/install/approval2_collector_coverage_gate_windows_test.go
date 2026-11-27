// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"strings"
	"testing"
	"time"
)

func stage3DServiceStarted() approval2CollectorRuntimeRecord {
	return approval2CollectorRuntimeRecord{
		Version:    approval2CollectorRuntimeVersion,
		RecordKind: "ServiceStarted",
		ObservedAt: "2026-10-12T13:00:01Z",
	}
}

func stage3DCatchUp(outcome, coverage, observedAt string) approval2CollectorRuntimeRecord {
	return approval2CollectorRuntimeRecord{
		Version:                approval2CollectorRuntimeVersion,
		RecordKind:             "WindowsSecurityCatchUp",
		ObservedAt:             observedAt,
		Outcome:                outcome,
		SecurityCoverageStatus: coverage,
	}
}

func stage3DNotBefore() time.Time {
	return time.Date(2026, time.October, 12, 13, 0, 0, 0, time.UTC)
}

func TestApproval2CoverageGateAcceptsCurrentReady(t *testing.T) {
	records := []approval2CollectorRuntimeRecord{
		stage3DServiceStarted(),
		stage3DCatchUp("Complete", "Ready", "2026-10-12T13:00:02Z"),
	}
	ready, err := inspectApproval2CollectorRuntimeReadiness(records, stage3DNotBefore())
	if err != nil || !ready {
		t.Fatalf("current Ready coverage rejected: ready=%t err=%v", ready, err)
	}
}

func TestApproval2CoverageGateRejectsMissingCoverage(t *testing.T) {
	records := []approval2CollectorRuntimeRecord{
		stage3DServiceStarted(),
		stage3DCatchUp("Complete", "", "2026-10-12T13:00:02Z"),
	}
	ready, err := inspectApproval2CollectorRuntimeReadiness(records, stage3DNotBefore())
	if ready || err == nil || !strings.Contains(err.Error(), "requires Ready") {
		t.Fatalf("missing coverage accepted: ready=%t err=%v", ready, err)
	}
}

func TestApproval2CoverageGateRejectsPartialCoverage(t *testing.T) {
	records := []approval2CollectorRuntimeRecord{
		stage3DServiceStarted(),
		stage3DCatchUp("Complete", "Partial", "2026-10-12T13:00:02Z"),
	}
	ready, err := inspectApproval2CollectorRuntimeReadiness(records, stage3DNotBefore())
	if ready || err == nil || !strings.Contains(err.Error(), "Partial") {
		t.Fatalf("Partial coverage accepted: ready=%t err=%v", ready, err)
	}
}

func TestApproval2CoverageGateRejectsStaleReadyCycle(t *testing.T) {
	records := []approval2CollectorRuntimeRecord{
		stage3DCatchUp("Complete", "Ready", "2026-10-12T13:00:01Z"),
		{Version: approval2CollectorRuntimeVersion, RecordKind: "ServiceStarted", ObservedAt: "2026-10-12T13:00:02Z"},
	}
	ready, err := inspectApproval2CollectorRuntimeReadiness(records, stage3DNotBefore())
	if err != nil || ready {
		t.Fatalf("stale Ready cycle accepted: ready=%t err=%v", ready, err)
	}
}

func TestApproval2CoverageGateRejectsReadyBeforeServiceStartTimestamp(t *testing.T) {
	records := []approval2CollectorRuntimeRecord{
		stage3DServiceStarted(),
		stage3DCatchUp("Complete", "Ready", "2026-10-12T13:00:00Z"),
	}
	ready, err := inspectApproval2CollectorRuntimeReadiness(records, stage3DNotBefore())
	if err != nil || ready {
		t.Fatalf("pre-service Ready cycle accepted: ready=%t err=%v", ready, err)
	}
}

func TestApproval2CoverageGateRequiresFreshReadyAfterRestart(t *testing.T) {
	records := []approval2CollectorRuntimeRecord{
		stage3DServiceStarted(),
		stage3DCatchUp("Complete", "Ready", "2026-10-12T13:00:02Z"),
		{Version: approval2CollectorRuntimeVersion, RecordKind: "ServiceStarted", ObservedAt: "2026-10-12T13:00:03Z"},
	}
	ready, err := inspectApproval2CollectorRuntimeReadiness(records, stage3DNotBefore())
	if err != nil || ready {
		t.Fatalf("prior process Ready cycle accepted: ready=%t err=%v", ready, err)
	}
	records = append(records, stage3DCatchUp("Complete", "Ready", "2026-10-12T13:00:04Z"))
	ready, err = inspectApproval2CollectorRuntimeReadiness(records, stage3DNotBefore())
	if err != nil || !ready {
		t.Fatalf("current process Ready cycle rejected: ready=%t err=%v", ready, err)
	}
}
