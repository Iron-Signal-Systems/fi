// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"context"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	fioperation "github.com/Iron-Signal-Systems/fi/go/internal/windows/operation"
)

// JournaledReobservationResult is the first operation-journal integration. It
// keeps the normal source batch unchanged while reporting the bounded USN-read
// and re-observation operations that produced it.
type JournaledReobservationResult struct {
	OperationJournalPath   string                  `json:"operation_journal_path"`
	USNReadOperation       records.OperationRecord `json:"usn_read_operation"`
	ReObservationOperation records.OperationRecord `json:"reobservation_operation"`
	Result                 ReobservationBatch      `json:"result"`
}

// ReadAndReobserveJournaled reads one USN batch, journals the USNRead outcome,
// re-observes distinct objects, then journals the ReObservation outcome.
//
// OutsideGovernedRoot and Unavailable are explicit expected per-object source
// outcomes and do not make the overall re-observation operation partial. Only
// ReobservationError makes the operation Partial. Context cancellation makes it
// Interrupted.
func ReadAndReobserveJournaled(
	ctx context.Context,
	scopeID string,
	governedRoot string,
	startUSN string,
) (JournaledReobservationResult, error) {
	journalPath, err := fioperation.DefaultJournalPath(scopeID)
	if err != nil {
		return JournaledReobservationResult{}, err
	}

	readStarted, err := fioperation.Start(scopeID, records.OperationUSNRead)
	if err != nil {
		return JournaledReobservationResult{}, err
	}
	batch, readErr := ReadJournal(ctx, scopeID, governedRoot, startUSN)
	if readErr != nil {
		readRecord, finishErr := readStarted.Finish(records.OperationFailed, "USNReadFailed")
		if finishErr != nil {
			return JournaledReobservationResult{}, finishErr
		}
		if appendErr := fioperation.Append(journalPath, readRecord); appendErr != nil {
			return JournaledReobservationResult{}, appendErr
		}
		return JournaledReobservationResult{}, readErr
	}
	readRecord, err := readStarted.Finish(records.OperationComplete, "")
	if err != nil {
		return JournaledReobservationResult{}, err
	}
	if err := fioperation.Append(journalPath, readRecord); err != nil {
		return JournaledReobservationResult{}, err
	}

	reobserveStarted, err := fioperation.Start(scopeID, records.OperationReObservation)
	if err != nil {
		return JournaledReobservationResult{}, err
	}
	result := ReobserveBatch(ctx, governedRoot, batch)

	outcome, reason := reobservationOperationOutcome(ctx, result)
	reobserveRecord, err := reobserveStarted.Finish(outcome, reason)
	if err != nil {
		return JournaledReobservationResult{}, err
	}
	if err := fioperation.Append(journalPath, reobserveRecord); err != nil {
		return JournaledReobservationResult{}, err
	}

	return JournaledReobservationResult{
		OperationJournalPath:   journalPath,
		USNReadOperation:       readRecord,
		ReObservationOperation: reobserveRecord,
		Result:                 result,
	}, nil
}

func reobservationOperationOutcome(
	ctx context.Context,
	result ReobservationBatch,
) (records.OperationOutcome, string) {
	if ctx.Err() != nil {
		return records.OperationInterrupted, "ContextCanceled"
	}
	for _, observation := range result.Reobservations {
		if observation.Status == ReobservationError {
			return records.OperationPartial, "OneOrMoreReobservationsFailed"
		}
	}
	return records.OperationComplete, ""
}
