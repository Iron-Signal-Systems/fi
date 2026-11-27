// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import "errors"

const (
	WindowsSecurityContinuityGapCoverageIncomplete            = "Incomplete"
	WindowsSecurityContinuityGapReconcileCurrentStateBaseline = "CurrentStateBaseline"
)

// WindowsSecurityContinuityGapObservation preserves the FI-owned Security-log
// checkpoint boundary and the available Windows Security log boundaries observed
// when FI proves continuity was lost. It does not claim which missing historical
// Security events existed or reconstruct them from current state.
type WindowsSecurityContinuityGapObservation struct {
	ObservedAt                 string `json:"observed_at"`
	CollectionMethod           string `json:"collection_method"`
	Channel                    string `json:"channel"`
	ScopeID                    string `json:"scope_id"`
	ReasonCode                 string `json:"reason_code"`
	CheckpointEventRecordID    string `json:"checkpoint_event_record_id"`
	CurrentOldestEventRecordID string `json:"current_oldest_event_record_id"`
	CurrentNewestEventRecordID string `json:"current_newest_event_record_id"`
	CoverageState              string `json:"coverage_state"`
	ReconciliationAction       string `json:"reconciliation_action"`
}

func ValidateWindowsSecurityContinuityGapObservation(value WindowsSecurityContinuityGapObservation) error {
	if err := ValidateObservedAt(value.ObservedAt); err != nil {
		return err
	}
	if value.CollectionMethod != WindowsSecurityCollectionMethod ||
		value.Channel != "Security" ||
		value.ScopeID == "" {
		return errors.New("invalid Windows Security continuity gap observation")
	}

	switch value.ReasonCode {
	case "SecurityLogResetOrCleared", "SecurityLogRecordsOverwritten":
	default:
		return errors.New("invalid Windows Security continuity gap reason")
	}

	for fieldName, fieldValue := range map[string]string{
		"checkpoint_event_record_id":     value.CheckpointEventRecordID,
		"current_oldest_event_record_id": value.CurrentOldestEventRecordID,
		"current_newest_event_record_id": value.CurrentNewestEventRecordID,
	} {
		if err := validateDecimal(fieldValue, "windows_security_continuity_gap."+fieldName); err != nil {
			return err
		}
	}

	if value.CoverageState != WindowsSecurityContinuityGapCoverageIncomplete ||
		value.ReconciliationAction != WindowsSecurityContinuityGapReconcileCurrentStateBaseline {
		return errors.New("invalid Windows Security continuity gap recovery state")
	}
	return nil
}
