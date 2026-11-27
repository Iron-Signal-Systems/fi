// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package securityevent

import (
	"errors"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestBrokerPolicyObservationsExactOrder(t *testing.T) {
	// Wire order: Audit Policy Change, File System, Handle Manipulation,
	// Detailed File Share. Preserve an unrelated high flag on File System.
	value, err := brokerPolicyObservations([]uint32{1, 0x83, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if value.PolicyChange.SubcategoryGUID != AuditPolicyChangeSubcategoryGUID ||
		!value.PolicyChange.SuccessEnabled || value.PolicyChange.FailureEnabled {
		t.Fatalf("unexpected Audit Policy Change: %+v", value.PolicyChange)
	}
	if value.FileSystem.SubcategoryGUID != FileSystemAuditSubcategoryGUID ||
		!value.FileSystem.SuccessEnabled || !value.FileSystem.FailureEnabled ||
		value.FileSystem.AuditingInformation != "131" {
		t.Fatalf("unexpected File System: %+v", value.FileSystem)
	}
	if value.HandleManipulation.SubcategoryGUID != HandleManipulationSubcategoryGUID ||
		value.HandleManipulation.SuccessEnabled || !value.HandleManipulation.FailureEnabled {
		t.Fatalf("unexpected Handle Manipulation: %+v", value.HandleManipulation)
	}
	if value.DetailedFileShare.SubcategoryGUID != DetailedFileShareSubcategoryGUID ||
		!value.DetailedFileShare.SuccessEnabled || !value.DetailedFileShare.FailureEnabled {
		t.Fatalf("unexpected Detailed File Share: %+v", value.DetailedFileShare)
	}
	roots := []records.WindowsSecurityRootAuditCoverage{{
		RecommendedChangeAuditPresent: true,
		RecommendedReadAuditPresent:   true,
	}}
	if got := coverageStatus(value.FileSystem, value.HandleManipulation, value.DetailedFileShare, value.PolicyChange, true, roots); got != records.WindowsSecurityCoverageReady {
		t.Fatalf("ready policies and SACL returned %q", got)
	}
}

func TestBrokerPolicyObservationsRejectsWrongCount(t *testing.T) {
	for _, flags := range [][]uint32{nil, {}, {1, 2, 3}, {1, 2, 3, 4, 5}} {
		if _, err := brokerPolicyObservations(flags); err == nil {
			t.Fatalf("unexpected acceptance of %d flags", len(flags))
		}
	}
}

func TestBrokerPolicyFailureMeansPartialCoverage(t *testing.T) {
	value := unknownBrokerRequiredAuditPolicies(errors.New("broker unavailable"))
	roots := []records.WindowsSecurityRootAuditCoverage{{
		RecommendedChangeAuditPresent: true,
		RecommendedReadAuditPresent:   true,
	}}
	if got := coverageStatus(value.FileSystem, value.HandleManipulation, value.DetailedFileShare, value.PolicyChange, true, roots); got != records.WindowsSecurityCoveragePartial {
		t.Fatalf("broker failure was incorrectly accepted as %q", got)
	}
	for _, p := range []records.WindowsSecurityAuditPolicyObservation{
		value.FileSystem, value.HandleManipulation, value.DetailedFileShare, value.PolicyChange,
	} {
		if p.AuditingInformation != "Unknown" || !strings.Contains(p.ReasonCode, "broker unavailable") {
			t.Fatalf("missing audit-policy failure reason: %+v", p)
		}
	}
}
