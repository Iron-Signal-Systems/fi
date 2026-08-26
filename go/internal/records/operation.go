// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package records

import (
	"errors"
	"strings"
	"time"
)

// OperationKind names a bounded FI collection operation. These are operational
// provenance records; they do not replace the source facts collected by FI.
type OperationKind string

const (
	OperationActivityRead           OperationKind = "ActivityRead"
	OperationBaseline               OperationKind = "Baseline"
	OperationProtectedRead          OperationKind = "ProtectedRead"
	OperationReconciliation         OperationKind = "Reconciliation"
	OperationReObservation          OperationKind = "ReObservation"
	OperationUSNCatchUp             OperationKind = "USNCatchUp"
	OperationUSNRead                OperationKind = "USNRead"
	OperationWindowsSecurityCatchUp OperationKind = "WindowsSecurityCatchUp"
)

// OperationOutcome records how a bounded FI operation ended.
type OperationOutcome string

const (
	OperationComplete    OperationOutcome = "Complete"
	OperationFailed      OperationOutcome = "Failed"
	OperationInterrupted OperationOutcome = "Interrupted"
	OperationPartial     OperationOutcome = "Partial"
)

// OperationRecord describes one completed or explicitly interrupted FI
// operation. It says what FI attempted and how that bounded operation ended.
// It does not infer anything about file history beyond the source records
// produced by that operation.
type OperationRecord struct {
	OperationID string           `json:"operation_id"`
	ScopeID     string           `json:"scope_id"`
	Kind        OperationKind    `json:"kind"`
	StartedAt   string           `json:"started_at"`
	FinishedAt  string           `json:"finished_at"`
	Outcome     OperationOutcome `json:"outcome"`
	ReasonCode  string           `json:"reason_code,omitempty"`
}

// ValidateOperationRecord enforces the stable Phase 1 operation-record shape.
func ValidateOperationRecord(value OperationRecord) error {
	if !validOperationID(value.OperationID) {
		return errors.New("InvalidOperationID: operation_id")
	}
	if strings.TrimSpace(value.ScopeID) == "" {
		return errors.New("Required: scope_id")
	}
	if !validOperationKind(value.Kind) {
		return errors.New("UnsupportedValue: kind")
	}
	started, err := parseOperationTimestamp(value.StartedAt)
	if err != nil {
		return errors.New("InvalidTimestamp: started_at")
	}
	finished, err := parseOperationTimestamp(value.FinishedAt)
	if err != nil {
		return errors.New("InvalidTimestamp: finished_at")
	}
	if finished.Before(started) {
		return errors.New("InvalidRange: finished_at")
	}
	if !validOperationOutcome(value.Outcome) {
		return errors.New("UnsupportedValue: outcome")
	}
	switch value.Outcome {
	case OperationComplete:
		return nil
	case OperationFailed, OperationInterrupted, OperationPartial:
		if strings.TrimSpace(value.ReasonCode) == "" {
			return errors.New("Required: reason_code")
		}
		return nil
	default:
		return errors.New("UnsupportedValue: outcome")
	}
}

func validOperationKind(value OperationKind) bool {
	switch value {
	case OperationActivityRead, OperationBaseline, OperationProtectedRead,
		OperationReconciliation, OperationReObservation, OperationUSNCatchUp,
		OperationUSNRead, OperationWindowsSecurityCatchUp:
		return true
	default:
		return false
	}
}

func validOperationOutcome(value OperationOutcome) bool {
	switch value {
	case OperationComplete, OperationFailed, OperationInterrupted, OperationPartial:
		return true
	default:
		return false
	}
}

func validOperationID(value string) bool {
	if len(value) != 35 || !strings.HasPrefix(value, "op-") {
		return false
	}
	for _, character := range value[3:] {
		switch {
		case character >= '0' && character <= '9':
		case character >= 'a' && character <= 'f':
		default:
			return false
		}
	}
	return true
}

func parseOperationTimestamp(value string) (time.Time, error) {
	const layout = "2006-01-02T15:04:05.000000000Z"
	if len(value) != len(layout) {
		return time.Time{}, errors.New("invalid timestamp")
	}
	parsed, err := time.Parse(layout, value)
	if err != nil || parsed.Format(layout) != value {
		return time.Time{}, errors.New("invalid timestamp")
	}
	return parsed, nil
}
