//go:build windows

package securityevent

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestCoverageStatusRequiresHandleManipulationFailureAndReadAudit(t *testing.T) {
	fileSystem := records.WindowsSecurityAuditPolicyObservation{
		SuccessEnabled: true,
		FailureEnabled: true,
	}
	handleManipulation := records.WindowsSecurityAuditPolicyObservation{}
	policyChange := records.WindowsSecurityAuditPolicyObservation{SuccessEnabled: true}
	roots := []records.WindowsSecurityRootAuditCoverage{{
		RecommendedChangeAuditPresent: true,
		RecommendedReadAuditPresent:   true,
	}}

	if got := coverageStatus(fileSystem, handleManipulation, policyChange, true, roots); got != records.WindowsSecurityCoveragePartial {
		t.Fatalf("without Handle Manipulation failure: got %q", got)
	}

	handleManipulation.FailureEnabled = true
	if got := coverageStatus(fileSystem, handleManipulation, policyChange, true, roots); got != records.WindowsSecurityCoverageReady {
		t.Fatalf("complete coverage: got %q", got)
	}

	roots[0].RecommendedReadAuditPresent = false
	if got := coverageStatus(fileSystem, handleManipulation, policyChange, true, roots); got != records.WindowsSecurityCoveragePartial {
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
