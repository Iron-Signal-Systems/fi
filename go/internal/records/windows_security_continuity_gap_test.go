package records

import "testing"

func TestValidateWindowsSecurityContinuityGapObservation(t *testing.T) {
	value := WindowsSecurityContinuityGapObservation{
		ObservedAt:                 "2026-08-26T12:00:00.123456700Z",
		CollectionMethod:           WindowsSecurityCollectionMethod,
		Channel:                    "Security",
		ScopeID:                    "windows-security-local",
		ReasonCode:                 "SecurityLogRecordsOverwritten",
		CheckpointEventRecordID:    "100",
		CurrentOldestEventRecordID: "200",
		CurrentNewestEventRecordID: "300",
		CoverageState:              WindowsSecurityContinuityGapCoverageIncomplete,
		ReconciliationAction:       WindowsSecurityContinuityGapReconcileCurrentStateBaseline,
	}
	if err := ValidateWindowsSecurityContinuityGapObservation(value); err != nil {
		t.Fatal(err)
	}
}

func TestValidateWindowsSecurityContinuityGapObservationRejectsUnknownReason(t *testing.T) {
	value := WindowsSecurityContinuityGapObservation{
		ObservedAt:                 "2026-08-26T12:00:00.123456700Z",
		CollectionMethod:           WindowsSecurityCollectionMethod,
		Channel:                    "Security",
		ScopeID:                    "windows-security-local",
		ReasonCode:                 "NotARealGap",
		CheckpointEventRecordID:    "100",
		CurrentOldestEventRecordID: "200",
		CurrentNewestEventRecordID: "300",
		CoverageState:              WindowsSecurityContinuityGapCoverageIncomplete,
		ReconciliationAction:       WindowsSecurityContinuityGapReconcileCurrentStateBaseline,
	}
	if err := ValidateWindowsSecurityContinuityGapObservation(value); err == nil {
		t.Fatal("unknown reason was accepted")
	}
}
