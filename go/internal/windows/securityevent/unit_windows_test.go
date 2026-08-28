// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package securityevent

import (
	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"strings"
	"testing"
)

func TestAssessCheckpointContinuous(t *testing.T) {
	value := Checkpoint{Version: securityCheckpointVersion, Channel: securityChannel, LastEventRecordID: "150", UpdatedAt: "2026-08-24T10:00:00Z"}
	state := LogState{OldestEventRecordID: "100", NewestEventRecordID: "200"}
	assessment, err := AssessCheckpoint(value, state)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Status != ContinuityContinuous {
		t.Fatalf("status=%s reason=%s", assessment.Status, assessment.ReasonCode)
	}
}

func TestAssessCheckpointOverwrittenGap(t *testing.T) {
	value := Checkpoint{Version: securityCheckpointVersion, Channel: securityChannel, LastEventRecordID: "50", UpdatedAt: "2026-08-24T10:00:00Z"}
	state := LogState{OldestEventRecordID: "100", NewestEventRecordID: "200"}
	assessment, err := AssessCheckpoint(value, state)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Status != ContinuityGap || assessment.ReasonCode != "SecurityLogRecordsOverwritten" {
		t.Fatalf("status=%s reason=%s", assessment.Status, assessment.ReasonCode)
	}
}

func TestAssessCheckpointResetGap(t *testing.T) {
	value := Checkpoint{Version: securityCheckpointVersion, Channel: securityChannel, LastEventRecordID: "500", UpdatedAt: "2026-08-24T10:00:00Z"}
	state := LogState{OldestEventRecordID: "1", NewestEventRecordID: "25"}
	assessment, err := AssessCheckpoint(value, state)
	if err != nil {
		t.Fatal(err)
	}
	if assessment.Status != ContinuityGap || assessment.ReasonCode != "SecurityLogResetOrCleared" {
		t.Fatalf("status=%s reason=%s", assessment.Status, assessment.ReasonCode)
	}
}

func TestCoverageStatusRequiresHandleManipulationDetailedFileShareAndReadAudit(t *testing.T) {
	fileSystem := records.WindowsSecurityAuditPolicyObservation{
		SuccessEnabled: true,
		FailureEnabled: true,
	}
	handleManipulation := records.WindowsSecurityAuditPolicyObservation{}
	detailedFileShare := records.WindowsSecurityAuditPolicyObservation{
		SuccessEnabled: true,
		FailureEnabled: true,
	}
	policyChange := records.WindowsSecurityAuditPolicyObservation{SuccessEnabled: true}
	roots := []records.WindowsSecurityRootAuditCoverage{{
		RecommendedChangeAuditPresent: true,
		RecommendedReadAuditPresent:   true,
	}}

	if got := coverageStatus(fileSystem, handleManipulation, detailedFileShare, policyChange, true, roots); got != records.WindowsSecurityCoveragePartial {
		t.Fatalf("without Handle Manipulation failure: got %q", got)
	}

	handleManipulation.FailureEnabled = true
	detailedFileShare.FailureEnabled = false
	if got := coverageStatus(fileSystem, handleManipulation, detailedFileShare, policyChange, true, roots); got != records.WindowsSecurityCoveragePartial {
		t.Fatalf("without Detailed File Share failure: got %q", got)
	}

	detailedFileShare.FailureEnabled = true
	detailedFileShare.SuccessEnabled = false
	if got := coverageStatus(fileSystem, handleManipulation, detailedFileShare, policyChange, true, roots); got != records.WindowsSecurityCoveragePartial {
		t.Fatalf("without Detailed File Share success: got %q", got)
	}

	detailedFileShare.SuccessEnabled = true
	if got := coverageStatus(fileSystem, handleManipulation, detailedFileShare, policyChange, true, roots); got != records.WindowsSecurityCoverageReady {
		t.Fatalf("complete coverage: got %q", got)
	}

	roots[0].RecommendedReadAuditPresent = false
	if got := coverageStatus(fileSystem, handleManipulation, detailedFileShare, policyChange, true, roots); got != records.WindowsSecurityCoveragePartial {
		t.Fatalf("without read audit: got %q", got)
	}
}

func TestHasRecommendedChangeAuditACE(t *testing.T) {
	sacl := records.SACLObservation{
		State: records.ObservationStatePresent,
		ACL: records.ACLObservation{
			State: records.ACLStatePresent,
			ACEs: []records.ACEObservation{{
				Type: "2", SID: "S-1-1-0", Mask: "852310", Flags: "195",
			}},
		},
	}

	if !hasRecommendedChangeAuditACE(sacl) {
		t.Fatal("recommended change-audit ACE not recognized")
	}
}

func TestHasRecommendedReadAuditACE(t *testing.T) {
	sacl := records.SACLObservation{
		State: records.ObservationStatePresent,
		ACL: records.ACLObservation{
			State: records.ACLStatePresent,
			ACEs: []records.ACEObservation{{
				Type: "2", SID: "S-1-1-0", Mask: "1", Flags: "201",
			}},
		},
	}

	if !hasRecommendedReadAuditACE(sacl) {
		t.Fatal("recommended file-read audit ACE not recognized")
	}

	sacl.ACL.ACEs[0].Flags = "200"
	if hasRecommendedReadAuditACE(sacl) {
		t.Fatal("file-read ACE without ObjectInherit was accepted")
	}
}

func TestRenderedEventXMLBufferUnitsRejectsEmptySize(t *testing.T) {
	for _, used := range []uint32{0, 1} {
		if _, err := renderedEventXMLBufferUnits(used); err == nil {
			t.Fatalf("used = %d: expected error", used)
		}
	}
}

func TestRenderedEventXMLBufferUnitsAcceptsBoundedSize(t *testing.T) {
	units, err := renderedEventXMLBufferUnits(maximumRenderedEventXMLBytes)
	if err != nil {
		t.Fatal(err)
	}
	if want := int(maximumRenderedEventXMLBytes / 2); units != want {
		t.Fatalf("units = %d, want %d", units, want)
	}
}

func TestRenderedEventXMLBufferUnitsRejectsOversizedSize(t *testing.T) {
	if _, err := renderedEventXMLBufferUnits(maximumRenderedEventXMLBytes + 1); err == nil {
		t.Fatal("expected oversized render rejection")
	}
}

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
