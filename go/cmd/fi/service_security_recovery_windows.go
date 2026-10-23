// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/securityevent"
)

// serviceWindowsSecurityRecoveryCheckpoint chooses the next durable checkpoint
// after a continuity gap has been recorded. An overwritten range has a still-
// readable suffix: resume at oldest-1 so no retained events are abandoned.
// A cleared/reset log has no valid retained-history continuation and follows
// the existing current-state reconciliation semantics.
func serviceWindowsSecurityRecoveryCheckpoint(
	assessment securityevent.ContinuityAssessment,
) (string, bool, error) {
	if assessment.Status != securityevent.ContinuityGap {
		return "", false, errors.New("Windows Security recovery requires a proven continuity gap")
	}

	switch assessment.ReasonCode {
	case "SecurityLogRecordsOverwritten":
		oldest, err := strconv.ParseUint(assessment.LogState.OldestEventRecordID, 10, 64)
		if err != nil {
			return "", false, fmt.Errorf("parse oldest retained Security EventRecordID: %w", err)
		}
		newest, err := strconv.ParseUint(assessment.LogState.NewestEventRecordID, 10, 64)
		if err != nil {
			return "", false, fmt.Errorf("parse newest retained Security EventRecordID: %w", err)
		}
		checkpoint, err := strconv.ParseUint(assessment.Checkpoint.LastEventRecordID, 10, 64)
		if err != nil {
			return "", false, fmt.Errorf("parse Security checkpoint EventRecordID: %w", err)
		}
		if oldest == 0 || oldest > newest || oldest-1 <= checkpoint {
			return "", false, errors.New("invalid retained Security event range for gap recovery")
		}
		return strconv.FormatUint(oldest-1, 10), true, nil

	case "SecurityLogResetOrCleared":
		newest, err := strconv.ParseUint(assessment.LogState.NewestEventRecordID, 10, 64)
		if err != nil {
			return "", false, fmt.Errorf("parse reset Security EventRecordID: %w", err)
		}
		return strconv.FormatUint(newest, 10), false, nil

	default:
		return "", false, fmt.Errorf("unsupported Windows Security continuity gap reason %q", assessment.ReasonCode)
	}
}
