package records

import "testing"

func TestValidateUSNContinuityGapObservation(t *testing.T) {
	value := USNContinuityGapObservation{
		ObservedAt:            "2026-08-26T12:00:00.000000000Z",
		CollectionMethod:      WindowsUSNCollectionMethod,
		ScopeID:               "root-a",
		GovernedRoot:          `C:\Data`,
		ReasonCode:            "JournalIDChanged",
		CheckpointJournalID:   "100",
		CheckpointNextUSN:     "200",
		CurrentJournalID:      "101",
		CurrentFirstUSN:       "300",
		CurrentLowestValidUSN: "300",
		CurrentNextUSN:        "400",
		CoverageState:         USNContinuityGapCoverageIncomplete,
		ReconciliationAction:  USNContinuityGapReconcileBaselineAndCatchUp,
	}
	if err := ValidateUSNContinuityGapObservation(value); err != nil {
		t.Fatal(err)
	}

	value.ReasonCode = ""
	if err := ValidateUSNContinuityGapObservation(value); err == nil {
		t.Fatal("missing reason code was accepted")
	}
}
