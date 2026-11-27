// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import "errors"

const (
	USNContinuityGapCoverageIncomplete          = "Incomplete"
	USNContinuityGapReconcileBaselineAndCatchUp = "CurrentStateBaselineAndUSNCatchUp"
	WindowsUSNCollectionMethod                  = "WindowsNTFSUSNJournalV0"
)

// USNContinuityGapObservation preserves the FI-owned checkpoint boundary and
// the current NTFS journal boundaries observed when continuity is broken. It
// does not claim which individual historical changes were lost.
type USNContinuityGapObservation struct {
	ObservedAt            string `json:"observed_at"`
	CollectionMethod      string `json:"collection_method"`
	ScopeID               string `json:"scope_id"`
	GovernedRoot          string `json:"governed_root"`
	ReasonCode            string `json:"reason_code"`
	CheckpointJournalID   string `json:"checkpoint_journal_id"`
	CheckpointNextUSN     string `json:"checkpoint_next_usn"`
	CurrentJournalID      string `json:"current_journal_id"`
	CurrentFirstUSN       string `json:"current_first_usn"`
	CurrentLowestValidUSN string `json:"current_lowest_valid_usn"`
	CurrentNextUSN        string `json:"current_next_usn"`
	CoverageState         string `json:"coverage_state"`
	ReconciliationAction  string `json:"reconciliation_action"`
}

func ValidateUSNContinuityGapObservation(value USNContinuityGapObservation) error {
	if err := ValidateObservedAt(value.ObservedAt); err != nil {
		return err
	}
	if value.CollectionMethod != WindowsUSNCollectionMethod ||
		value.ScopeID == "" ||
		value.GovernedRoot == "" ||
		value.ReasonCode == "" ||
		value.CoverageState != USNContinuityGapCoverageIncomplete ||
		value.ReconciliationAction != USNContinuityGapReconcileBaselineAndCatchUp {
		return errors.New("invalid USN continuity gap observation")
	}

	for fieldName, fieldValue := range map[string]string{
		"checkpoint_journal_id":    value.CheckpointJournalID,
		"checkpoint_next_usn":      value.CheckpointNextUSN,
		"current_journal_id":       value.CurrentJournalID,
		"current_first_usn":        value.CurrentFirstUSN,
		"current_lowest_valid_usn": value.CurrentLowestValidUSN,
		"current_next_usn":         value.CurrentNextUSN,
	} {
		if err := validateDecimal(fieldValue, "usn_continuity_gap."+fieldName); err != nil {
			return err
		}
	}
	return nil
}
