// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"context"
	"errors"
	"path/filepath"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/objbroker"
	fioperation "github.com/Iron-Signal-Systems/fi/go/internal/windows/operation"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/resourcejournal"
)

type interruptedRecoverySuppressedKey struct{}

// WithoutInterruptedRecovery marks a nested USN operation whose caller has
// already performed scope-level restart recovery before durably starting its
// parent operation. This prevents a nested USN read from mistaking that live
// parent Started entry for an operation abandoned by an earlier FI process.
func WithoutInterruptedRecovery(ctx context.Context) context.Context {
	return context.WithValue(ctx, interruptedRecoverySuppressedKey{}, struct{}{})
}

func shouldRecoverInterrupted(ctx context.Context) bool {
	_, suppressed := ctx.Value(interruptedRecoverySuppressedKey{}).(struct{})
	return !suppressed
}

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
	Stage                  *StagedReobservations   `json:"-"`
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
// By default, standalone callers recover operations abandoned by an earlier FI
// process before beginning new work. A configured parent operation performs that
// recovery once at its own scope boundary and passes WithoutInterruptedRecovery
// to nested USN work so the live parent cannot be closed as ProcessRestart.
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
	return readAndReobserveJournaled(ctx, scopeID, governedRoot, startUSN, false, "", 0, 0)
}

// ReadAndReobserveJournaledStaged keeps the existing operation lifecycle and
// original USN batch, but stages full NTFS observations outside the Go heap.
// The caller owns result.Stage and must close it after verified spool/SID work.
func ReadAndReobserveJournaledStaged(
	ctx context.Context, scopeID, governedRoot, startUSN, statePath string,
	chunkObjects, maxInflight int,
) (JournaledReobservationResult, error) {
	return readAndReobserveJournaled(ctx, scopeID, governedRoot, startUSN, true, filepath.Dir(statePath), chunkObjects, maxInflight)
}

func readAndReobserveJournaled(
	ctx context.Context, scopeID, governedRoot, startUSN string,
	staged bool, stageDir string, chunkObjects, maxInflight int,
) (JournaledReobservationResult, error) {
	operationJournalPath, err := fioperation.DefaultJournalPath(scopeID)
	if err != nil {
		return JournaledReobservationResult{}, err
	}
	resourceJournalPath, err := resourcejournal.DefaultPath(scopeID)
	if err != nil {
		return JournaledReobservationResult{}, err
	}

	if shouldRecoverInterrupted(ctx) {
		if _, err := fioperation.RecoverInterrupted(operationJournalPath, scopeID); err != nil {
			return JournaledReobservationResult{}, err
		}
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

	var result ReobservationBatch
	var stage *StagedReobservations
	var stageErr error
	if staged {
		result, stage, stageErr = stageReobservationBatch(
			ctx, governedRoot, batch, stageDir,
			currentReobserveWorkers(), chunkObjects, maxInflight,
			ntfs.CollectFileReference, objbroker.ObserveObject, CheckObjectContainment,
		)
	} else {
		result = ReobserveBatch(ctx, governedRoot, batch)
	}
	reobserveResourceErr := reobserveResources.Finish()
	if stageErr != nil {
		return JournaledReobservationResult{}, errors.Join(
			stageErr, reobserveResourceErr,
			finishFailedOperation(operationJournalPath, reobserveStarted, "USNObservationStagingFailed"),
		)
	}
	// The caller must close stage; otherwise errors after staging would leak
	// a temporary file until process exit.
	cleanupStage := true
	defer func() {
		if cleanupStage && stage != nil {
			_ = stage.Close()
		}
	}()

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

	cleanupStage = false
	return JournaledReobservationResult{
		OperationJournalPath:   operationJournalPath,
		ResourceJournalPath:    resourceJournalPath,
		USNReadOperation:       readRecord,
		ReObservationOperation: reobserveRecord,
		Result:                 result,
		Stage:                  stage,
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

// ReobserveCapturedJournaledStaged replays a durable, previously read USN batch
// into the existing bounded NTFS observation stage. Unlike the synchronous
// reader it DOES NOT call FSCTL_READ_USN_JOURNAL, check a live source position,
// advance any checkpoint, or fabricate a new USNRead operation. NTFS state is
// observed NOW, and may differ from the historical event time.
//
// This is an inactive M3 adapter. The caller must correlate the original batch,
// publish every required source event to verified FI custody, and advance only
// the independent processing cursor after that publication is proved.
func ReobserveCapturedJournaledStaged(
	ctx context.Context,
	scopeID, governedRoot string,
	batch records.USNReadBatch,
	statePath string,
	chunkObjects, maxInflight int,
) (JournaledReobservationResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return JournaledReobservationResult{}, errors.New("cached USN observation requires a live context")
	}
	if batch.ScopeID != scopeID {
		return JournaledReobservationResult{}, errors.New("cached USN batch scope mismatch")
	}
	if err := records.ValidateUSNReadBatch(batch); err != nil {
		return JournaledReobservationResult{}, err
	}
	operationPath, err := fioperation.DefaultJournalPath(scopeID)
	if err != nil {
		return JournaledReobservationResult{}, err
	}
	resourcePath, err := resourcejournal.DefaultPath(scopeID)
	if err != nil {
		return JournaledReobservationResult{}, err
	}
	if shouldRecoverInterrupted(ctx) {
		if _, err := fioperation.RecoverInterrupted(operationPath, scopeID); err != nil {
			return JournaledReobservationResult{}, err
		}
	}
	started, err := fioperation.Start(scopeID, records.OperationReObservation)
	if err != nil {
		return JournaledReobservationResult{}, err
	}
	if err := fioperation.AppendStarted(operationPath, started); err != nil {
		return JournaledReobservationResult{}, err
	}
	resources, err := resourcejournal.Start(resourcePath, started.OperationID, started.ScopeID, started.Kind)
	if err != nil {
		return JournaledReobservationResult{}, errors.Join(err,
			finishFailedOperation(operationPath, started, "ResourceJournalStartFailed"))
	}
	result, stage, stageErr := stageReobservationBatch(
		ctx, governedRoot, batch, filepath.Dir(statePath),
		currentReobserveWorkers(), chunkObjects, maxInflight,
		ntfs.CollectFileReference, objbroker.ObserveObject, CheckObjectContainment,
	)
	resourcesErr := resources.Finish()
	if stageErr != nil {
		return JournaledReobservationResult{}, errors.Join(stageErr, resourcesErr,
			finishFailedOperation(operationPath, started, "CachedUSNObservationStagingFailed"))
	}
	keepStage := false
	defer func() {
		if !keepStage && stage != nil {
			_ = stage.Close()
		}
	}()
	outcome, reason := reobservationOperationOutcome(ctx, result)
	completed, err := started.Finish(outcome, reason)
	if err != nil {
		return JournaledReobservationResult{}, errors.Join(err, resourcesErr)
	}
	if err := fioperation.AppendFinished(operationPath, completed); err != nil {
		return JournaledReobservationResult{}, errors.Join(err, resourcesErr)
	}
	if resourcesErr != nil {
		return JournaledReobservationResult{}, resourcesErr
	}
	keepStage = true
	return JournaledReobservationResult{
		OperationJournalPath:   operationPath,
		ResourceJournalPath:    resourcePath,
		ReObservationOperation: completed,
		Result:                 result,
		Stage:                  stage,
	}, nil
}
