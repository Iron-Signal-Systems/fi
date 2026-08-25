package records

import "testing"

func TestValidateWindowsSecurityEventObservation(t *testing.T) {
	value := WindowsSecurityEventObservation{
		ObservedAt:       "2026-08-24T10:00:00.000000000Z",
		CollectionMethod: WindowsSecurityCollectionMethod,
		Channel:          "Security",
		Provider:         "Microsoft-Windows-Security-Auditing",
		EventID:          "4656",
		EventRecordID:    "123",
		TimeCreated:      "2026-08-24T10:00:00.000000000Z",
		Computer:         "ISS-FS-01.iss.local",
		AuditResult:      WindowsSecurityAuditFailure,
		ScopeBasis:       WindowsSecurityScopePathMatched,
		MatchedScopes:    []WindowsSecurityMatchedScope{{ScopeID: "root-a", GovernedRoot: `C:\Data`}},
		Fields:           []WindowsSecurityEventField{},
		RawXML:           "<Event/>",
	}
	if err := ValidateWindowsSecurityEventObservation(value); err != nil {
		t.Fatal(err)
	}
}

func TestValidateWindowsSecurityCoverageObservation(t *testing.T) {
	value := WindowsSecurityCoverageObservation{
		ObservedAt:          "2026-08-25T09:00:00.000000000Z",
		CollectionMethod:    WindowsSecurityCollectionMethod,
		SecurityLogReadable: true,
		FileSystemPolicy: WindowsSecurityAuditPolicyObservation{
			SubcategoryGUID:     "{0CCE921D-69AE-11D9-BED3-505054503030}",
			AuditingInformation: "3",
			SuccessEnabled:      true,
			FailureEnabled:      true,
		},
		HandleManipulationPolicy: WindowsSecurityAuditPolicyObservation{
			SubcategoryGUID:     "{0CCE9223-69AE-11D9-BED3-505054503030}",
			AuditingInformation: "2",
			FailureEnabled:      true,
		},
		AuditPolicyChangePolicy: WindowsSecurityAuditPolicyObservation{
			SubcategoryGUID:     "{0CCE922F-69AE-11D9-BED3-505054503030}",
			AuditingInformation: "1",
			SuccessEnabled:      true,
		},
		Roots:  []WindowsSecurityRootAuditCoverage{},
		Status: WindowsSecurityCoverageReady,
	}

	if err := ValidateWindowsSecurityCoverageObservation(value); err != nil {
		t.Fatal(err)
	}

	value.HandleManipulationPolicy = WindowsSecurityAuditPolicyObservation{}

	if err := ValidateWindowsSecurityCoverageObservation(value); err == nil {
		t.Fatal("missing Handle Manipulation policy was accepted")
	}
}
