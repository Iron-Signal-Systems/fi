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
