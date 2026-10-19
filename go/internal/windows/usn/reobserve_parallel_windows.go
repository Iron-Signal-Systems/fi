// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import (
	"context"
	"sync"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

// Second performance experiment: eight bounded object observers per USN batch.
// This does not alter journal reads, spool order, durability, or checkpoints.
const reobserveWorkerCount = 8

func reobserveBatchWithWorkers(
	ctx context.Context,
	governedRoot string,
	batch records.USNReadBatch,
	collect fileReferenceCollector,
	observeBackup backupObjectObserver,
	checkContainment containmentChecker,
	workers int,
) ReobservationBatch {
	if ctx == nil {
		ctx = context.Background()
	}
	candidates := distinctReobservationCandidates(batch.Records)
	result := ReobservationBatch{
		USNBatch:       batch,
		Reobservations: make([]ChangeReobservation, len(candidates)),
	}
	if len(candidates) == 0 {
		return result
	}

	if workers < 1 {
		workers = 1
	}
	if workers > len(candidates) {
		workers = len(candidates)
	}

	// The unbuffered channel bounds queued work. Each worker writes only its
	// own result slot. Publication follows Wait, preserving original USN order.
	jobs := make(chan int)
	var group sync.WaitGroup
	group.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer group.Done()
			for index := range jobs {
				result.Reobservations[index] = reobserveCandidate(
					ctx, governedRoot, batch.ScopeID, candidates[index],
					collect, observeBackup, checkContainment,
				)
			}
		}()
	}
	for index := range candidates {
		jobs <- index
	}
	close(jobs)
	group.Wait()
	return result
}

// Preserve the original, narrow per-object error and privilege-fallback rules.
func reobserveCandidate(
	ctx context.Context,
	governedRoot string,
	scopeID string,
	candidate reobservationCandidate,
	collect fileReferenceCollector,
	observeBackup backupObjectObserver,
	checkContainment containmentChecker,
) ChangeReobservation {
	if err := validateContext(ctx); err != nil {
		return ChangeReobservation{
			FileIdentity: candidate.identity,
			TriggerUSNs:  candidate.triggerUSNs,
			Status:       ReobservationError,
			ReasonCode:   "ContextCanceled",
			Error:        err.Error(),
		}
	}

	observation, err := collect(ctx, scopeID, governedRoot, candidate.identity)
	if err == nil {
		return observedReobservation(candidate, observation)
	}
	if IsOpenFileByIDAccessDenied(err) {
		backupObservation, backupErr := observeBackup(ctx, governedRoot, candidate.identity)
		if backupErr == nil {
			return observedReobservation(candidate, backupObservation)
		}
		return classifyBackupAuthorityFailure(
			ctx, governedRoot, candidate, err, backupErr, checkContainment,
		)
	}
	status, reason := classifyReobservationError(err)
	return ChangeReobservation{
		FileIdentity: candidate.identity,
		TriggerUSNs:  candidate.triggerUSNs,
		Status:       status,
		ReasonCode:   reason,
		Error:        err.Error(),
	}
}

// Verify dependencies keep using the original NTFS per-handle collection path.
var _ fileReferenceCollector = ntfs.CollectFileReference
