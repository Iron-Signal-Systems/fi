// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"context"
	"errors"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	fioperation "github.com/Iron-Signal-Systems/fi/go/internal/windows/operation"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/resourcejournal"
)

// JournaledReobservationResult keeps the normal source batch unchanged while
// reporting the bounded USN-read and re-observation operations that produced it.
// Operational lifecycle and FI process-resource history are written to separate
// JSONL journals and correlated only by OperationID.
type JournaledReobservationResult struct {
	OperationJournalPath   string                  `json:"operation_journal_path"`
	ResourceJournalPath    string                  `json:"resource_journal_path"`
	USNReadOperation       records.OperationRecord `json:"usn_read_operation"`
	ReObservationOperation records.OperationRecord `json:"reobservation_operation"`
	Result                 ReobservationBatch      `json:"result"`
}

// ReadAndReobserveJournaled reads one USN batch, journals the USNRead lifecycle,
// re-observes distinct objects, then journals the ReObservation lifecycle.
//
// A Started entry is flushed to the operation journal before each bounded source
// operation begins. FI process CPU, RAM, and I/O are recorded separately in the
// resource journal with the same OperationID. Resource tracking writes one
// immediate sample, periodic five-second samples while an operation is running,
// and one final summary.
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
	operationJournalPath, err := fioperation.DefaultJournalPath(scopeID)
	if err != nil {
		return JournaledReobservationResult{}, err
	}
	resourceJournalPath, err := resourcejournal.DefaultPath(scopeID)
	if err != nil {
		return JournaledReobservationResult{}, err
	}

	// Close operations that were durably Started by an earlier FI process but
	// never received a terminal entry. Recovery runs before this invocation
	// starts any new bounded operation, so a currently running operation can
	// never be mistaken for an abandoned one.
	if _, err := fioperation.RecoverInterrupted(operationJournalPath, scopeID); err != nil {
		return JournaledReobservationResult{}, err
	}

	readStarted, err := fioperation.Start(scopeID, records.OperationUSNRead)
	if err != nil {
		return JournaledReobservationResult{}, err
	}
	if err := fioperation.AppendStarted(operationJournalPath, readStarted); err != nil {
		return JournaledReobservationResult{}, err
	}

	readResources, err := resourcejournal.Start(
		resourceJournalPath,
		readStarted.OperationID,
		readStarted.ScopeID,
		readStarted.Kind,
	)
	if err != nil {
		return JournaledReobservationResult{}, errors.Join(
			err,
			finishFailedOperation(
				operationJournalPath,
				readStarted,
				"ResourceJournalStartFailed",
			),
		)
	}

	batch, readErr := ReadJournal(ctx, scopeID, governedRoot, startUSN)
	readResourceErr := readResources.Finish()

	if readErr != nil {
		return JournaledReobservationResult{}, errors.Join(
			readErr,
			readResourceErr,
			finishFailedOperation(operationJournalPath, readStarted, "USNReadFailed"),
		)
	}

	readRecord, err := readStarted.Finish(records.OperationComplete, "")
	if err != nil {
		return JournaledReobservationResult{}, errors.Join(err, readResourceErr)
	}
	if appendErr := fioperation.AppendFinished(operationJournalPath, readRecord); appendErr != nil {
		return JournaledReobservationResult{}, errors.Join(appendErr, readResourceErr)
	}
	if readResourceErr != nil {
		return JournaledReobservationResult{}, readResourceErr
	}

	reobserveStarted, err := fioperation.Start(scopeID, records.OperationReObservation)
	if err != nil {
		return JournaledReobservationResult{}, err
	}
	if err := fioperation.AppendStarted(operationJournalPath, reobserveStarted); err != nil {
		return JournaledReobservationResult{}, err
	}

	reobserveResources, err := resourcejournal.Start(
		resourceJournalPath,
		reobserveStarted.OperationID,
		reobserveStarted.ScopeID,
		reobserveStarted.Kind,
	)
	if err != nil {
		return JournaledReobservationResult{}, errors.Join(
			err,
			finishFailedOperation(
				operationJournalPath,
				reobserveStarted,
				"ResourceJournalStartFailed",
			),
		)
	}

	result := ReobserveBatch(ctx, governedRoot, batch)
	reobserveResourceErr := reobserveResources.Finish()

	outcome, reason := reobservationOperationOutcome(ctx, result)
	reobserveRecord, err := reobserveStarted.Finish(outcome, reason)
	if err != nil {
		return JournaledReobservationResult{}, errors.Join(err, reobserveResourceErr)
	}
	if appendErr := fioperation.AppendFinished(operationJournalPath, reobserveRecord); appendErr != nil {
		return JournaledReobservationResult{}, errors.Join(appendErr, reobserveResourceErr)
	}
	if reobserveResourceErr != nil {
		return JournaledReobservationResult{}, reobserveResourceErr
	}

	return JournaledReobservationResult{
		OperationJournalPath:   operationJournalPath,
		ResourceJournalPath:    resourceJournalPath,
		USNReadOperation:       readRecord,
		ReObservationOperation: reobserveRecord,
		Result:                 result,
	}, nil
}

func finishFailedOperation(
	journalPath string,
	started fioperation.Started,
	reason string,
) error {
	record, err := started.Finish(records.OperationFailed, reason)
	if err != nil {
		return err
	}
	return fioperation.AppendFinished(journalPath, record)
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
