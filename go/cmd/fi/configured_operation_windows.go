// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"errors"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/operation"
)

func operationFailureReason(kind records.OperationKind) string {
	switch kind {
	case records.OperationBaseline:
		return "BaselineFailed"
	case records.OperationReconciliation:
		return "ReconciliationFailed"
	case records.OperationUSNCatchUp:
		return "USNCatchUpFailed"
	case records.OperationWindowsSecurityCatchUp:
		return "WindowsSecurityCatchUpFailed"
	default:
		return "OperationFailed"
	}
}

func recoverConfiguredOperations(scopeID string) (string, []records.OperationRecord, error) {
	path, err := operation.DefaultJournalPath(scopeID)
	if err != nil {
		return "", nil, err
	}
	recovered, err := operation.RecoverInterrupted(path, scopeID)
	return path, recovered, err
}

// appendConfiguredOperation appends only a real terminal operation record.
// Failures before a durable Started entry exists return the zero value from
// runConfiguredOperation and must not appear in user-visible operation summaries
// as a phantom operation.
func appendConfiguredOperation(
	operations []records.OperationRecord,
	record records.OperationRecord,
) []records.OperationRecord {
	if record.OperationID == "" {
		return operations
	}
	return append(operations, record)
}

func runConfiguredOperation(scopeID string, kind records.OperationKind, body func() error) (records.OperationRecord, error) {
	path, err := operation.DefaultJournalPath(scopeID)
	if err != nil {
		return records.OperationRecord{}, err
	}
	started, err := operation.Start(scopeID, kind)
	if err != nil {
		return records.OperationRecord{}, err
	}
	if err := operation.AppendStarted(path, started); err != nil {
		return records.OperationRecord{}, err
	}

	bodyErr := body()
	outcome := records.OperationComplete
	reasonCode := ""
	if bodyErr != nil {
		outcome = records.OperationFailed
		reasonCode = operationFailureReason(kind)
	}

	record, finishErr := started.Finish(outcome, reasonCode)
	if finishErr == nil {
		finishErr = operation.AppendFinished(path, record)
	}
	return record, errors.Join(bodyErr, finishErr)
}
