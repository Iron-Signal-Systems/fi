//go:build windows

package securityevent

import (
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestCoverageStatusRequiresHandleManipulationFailure(t *testing.T) {
	fileSystem := records.WindowsSecurityAuditPolicyObservation{
		SuccessEnabled: true,
		FailureEnabled: true,
	}

	handleManipulation := records.WindowsSecurityAuditPolicyObservation{}

	policyChange := records.WindowsSecurityAuditPolicyObservation{
		SuccessEnabled: true,
	}

	roots := []records.WindowsSecurityRootAuditCoverage{
		{
			RecommendedChangeAuditPresent: true,
		},
	}

	status := coverageStatus(
		fileSystem,
		handleManipulation,
		policyChange,
		true,
		roots,
	)

	if status != records.WindowsSecurityCoveragePartial {
		t.Fatalf(
			"coverage status = %q, want %q",
			status,
			records.WindowsSecurityCoveragePartial,
		)
	}

	handleManipulation.FailureEnabled = true

	status = coverageStatus(
		fileSystem,
		handleManipulation,
		policyChange,
		true,
		roots,
	)

	if status != records.WindowsSecurityCoverageReady {
		t.Fatalf(
			"coverage status = %q, want %q",
			status,
			records.WindowsSecurityCoverageReady,
		)
	}
}

func TestHasRecommendedAuditACE(t *testing.T) {
	sacl := records.SACLObservation{
		State: records.ObservationStatePresent,
		ACL: records.ACLObservation{
			State: records.ACLStatePresent,
			ACEs: []records.ACEObservation{
				{
					Type:  "2",
					SID:   "S-1-1-0",
					Mask:  "852310",
					Flags: "195",
				},
			},
		},
	}

	if !hasRecommendedAuditACE(sacl) {
		t.Fatal("recommended ACE not recognized")
	}
}
