// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
	"testing"
	"time"
)

func committedSecurityTestInput() (IngestResult, ingestStageProfile, securityBulkLimits) {
	result := IngestResult{Outcome: "Accepted", RecordsSeen: 16384, RecordsCommitted: 16384}
	profile := ingestStageProfile{}
	profile.SecurityBulk.Events = 16384
	profile.SecurityBulk.Fields = 245760
	profile.SecurityBulk.SourceBytes = 64 << 20
	profile.SecurityBulk.MaxContiguousSecurity = 16384
	limits, _ := securityBulkFixedProfile("P3")
	return result, profile, limits
}

func TestCommittedSecurityEvidenceRequiresConfirmedCommit(t *testing.T) {
	result, profile, limits := committedSecurityTestInput()
	got := committedSecurityIngestMetrics(result, &profile, limits, 7*time.Second)
	if got == nil || got.Profile != "P3" || got.Events != 16384 ||
		got.Fields != 245760 || got.SourceBytes != 64<<20 ||
		got.MaxContiguousSecurity != 16384 || got.Duration != 7*time.Second {
		t.Fatalf("committed metrics mismatch: %+v", got)
	}
	for _, outcome := range []string{"AlreadyAccepted", "Rejected", "Failed", ""} {
		result.Outcome = outcome
		if got := committedSecurityIngestMetrics(result, &profile, limits, time.Second); got != nil {
			t.Fatalf("outcome %q created metrics: %+v", outcome, got)
		}
	}
}

func TestCommittedSecurityEvidenceRejectsIncompleteCounts(t *testing.T) {
	result, profile, limits := committedSecurityTestInput()
	assertNil := func(name string, r IngestResult, p *ingestStageProfile, l securityBulkLimits, d time.Duration) {
		t.Helper()
		if got := committedSecurityIngestMetrics(r, p, l, d); got != nil {
			t.Fatalf("%s published metrics: %+v", name, got)
		}
	}
	assertNil("missing profile", result, nil, limits, time.Second)
	assertNil("zero duration", result, &profile, limits, 0)
	assertNil("missing profile name", result, &profile, securityBulkLimits{}, time.Second)
	result.RecordsCommitted--
	assertNil("uncommitted count", result, &profile, limits, time.Second)
	result.RecordsCommitted++
	profile.SecurityBulk.Events = 0
	assertNil("no security", result, &profile, limits, time.Second)
	profile.SecurityBulk.Events = 16385
	assertNil("event count exceeds committed source", result, &profile, limits, time.Second)
	profile.SecurityBulk.Events = 16384
	profile.SecurityBulk.SourceBytes = 0
	assertNil("no source bytes", result, &profile, limits, time.Second)
	profile.SecurityBulk.SourceBytes = 64 << 20
	profile.SecurityBulk.MaxContiguousSecurity = 16385
	assertNil("impossible security run", result, &profile, limits, time.Second)
}

// A multi-kind generation is still legitimately observable. The adaptive
// decision controller must separately reject unlike workloads for comparison.
func TestCommittedSecurityEvidenceDoesNotMislabelMixedGenerations(t *testing.T) {
	result, profile, limits := committedSecurityTestInput()
	result.RecordsSeen = 20000
	result.RecordsCommitted = 20000
	got := committedSecurityIngestMetrics(result, &profile, limits, time.Second)
	if got == nil || got.Events != 16384 {
		t.Fatalf("mixed generation evidence lost: %+v", got)
	}
	if got.Events == result.RecordsCommitted {
		t.Fatal("security event count incorrectly equated with all source records")
	}
}
