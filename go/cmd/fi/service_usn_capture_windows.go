// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "context"
    "errors"
    "fmt"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
    "github.com/Iron-Signal-Systems/fi/go/internal/windows/usn"
)

// usnRawCaptureOnce is the fast, source-only capture boundary. It MUST NEVER
// perform NTFS re-observation, hashing, scoped filtering, or FI spool processing.
type usnRawCaptureOnce func(context.Context) (bool, error)

// drainUSNCapture reads a bounded number of immutable raw source segments.
// It yields between bursts so other workers remain schedulable while capture
// can resume immediately if the NTFS journal is producing a high change rate.
func drainUSNCapture(ctx context.Context, capture usnRawCaptureOnce, maxBatches int) (int, bool, error) {
    if ctx == nil || capture == nil || maxBatches <= 0 {
        return 0, false, errors.New("invalid raw USN capture drain dependencies")
    }
    for count := 0; count < maxBatches; count++ {
        if err := ctx.Err(); err != nil {
            return count, false, err
        }
        advanced, err := capture(ctx)
        if err != nil {
            return count, false, err
        }
        if !advanced {
            return count, false, nil
        }
        if count+1 == maxBatches {
            return maxBatches, true, nil
        }
    }
    return 0, false, errors.New("unreachable capture drain")
}

// runServiceUSNRawCapture is the service-side capture lane (not the historical
// checkpoint-driven catch-up lane). An explicit, previously initialized queue
// must exist: no auto-init and no checkpoint rebasing on a continuity gap.
//
// WIRING GATE: This is deliberately not yet selected by -service. A separate
// processing/correlation worker and reviewed configuration migration MUST be
// completed before enabling the mode on any existing FI installation.
func runServiceUSNRawCapture(
    ctx context.Context,
    interval time.Duration,
    scopeID, governedRoot, queueDir string,
    maxPendingBytes uint64,
    appendRecord serviceAppendRecordFunc,
) error {
    if ctx == nil || interval <= 0 || appendRecord == nil || scopeID == "" || governedRoot == "" {
        return errors.New("invalid USN capture worker configuration")
    }

    // The queue is a volume-owned source journal, not a root-specific
    // work directory. Hold its kernel file lock for the ENTIRE worker
    // lifetime, including recovery and every cursor publication.
    // Acquiring it BEFORE Open rules out a second collector racing recovery.
    owner, err := usncapture.AcquireCaptureOwner(queueDir)
    if err != nil {
        return fmt.Errorf("acquire exclusive NTFS volume source owner: %w", err)
    }
    defer owner.Close()
    store, err := usncapture.Open(queueDir, maxPendingBytes)
    if err != nil {
        return fmt.Errorf("open durable raw USN capture queue: %w", err)
    }
    return runServiceUSNRawCaptureStore(
        ctx,interval,scopeID,governedRoot,store,appendRecord,
    )
}

// runServiceUSNRawCaptureStore holds no ownership lock itself: its caller
// must hold the exact per-volume owner for the entire worker lifetime. The
// same Store pointer may be shared with the independent processing worker.
func runServiceUSNRawCaptureStore(
    ctx context.Context,
    interval time.Duration,
    scopeID,governedRoot string,
    store *usncapture.Store,
    appendRecord serviceAppendRecordFunc,
) error {
    if ctx==nil||interval<=0||store==nil||scopeID==""||governedRoot==""||appendRecord==nil {
        return errors.New("FI raw capture worker requires original owner, source and telemetry")
    }
    if store.CaptureCursor().ScopeID != scopeID {
        return fmt.Errorf("%w: capture queue scope mismatch", usncapture.ErrConflict)
    }
    // Deliberately no serviceRootLocks.lockFor(): baseline / re-observation
    // must not make raw source capture wait behind a long-running root lock.
    // Cross-process exclusion is held above. Multi-root volume deduplication,
    // separately governed processing and service migration remain release gates.
    const burst = 512
    const reportInterval = 10 * time.Second

    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    lastReport := time.Now().Add(-reportInterval)
    capturedSinceReport := 0

    captureOnce := func(ctx context.Context) (bool, error) {
        return captureUSNOnce(ctx, scopeID, governedRoot, store)
    }
    for {
        if err := ctx.Err(); err != nil {
            return nil
        }
        count, saturated, captureErr := drainUSNCapture(ctx, captureOnce, burst)
        if captureErr != nil && ctx.Err() != nil {
            return nil
        }
        capturedSinceReport += count
        now := time.Now()
        if captureErr != nil || now.Sub(lastReport) >= reportInterval {
            outcome := serviceOutcomeComplete
            if captureErr != nil {
                outcome = serviceOutcomeFailed
            }
            record := serviceRuntimeRecord{
                Version:          serviceRuntimeVersion,
                RecordKind:       "USNRawCapture",
                ObservedAt:       serviceNow(),
                USNInterval:      interval.String(),
                Outcome:          outcome,
                ScopeID:          scopeID,
                CapturedBatches:  capturedSinceReport,
                CaptureNextUSN:   store.CaptureCursor().NextUSN,
                ProcessedNextUSN: store.ProcessingCursor().NextUSN,
                CaptureQueueBytes: store.PendingBytes(),
            }
            if captureErr != nil {
                record.Error = captureErr.Error()
            }
            // Operator telemetry needs live FirstUSN to prove capture is
            // keeping ahead of Windows journal retention. Telemetry failure
            // is visible but must not advance or rebase either cursor.
            state, queryErr := usn.QueryJournal(ctx, scopeID, governedRoot)
            if queryErr == nil {
                record.JournalFirstUSN = state.FirstUSN
                record.JournalNextUSN = state.NextUSN
            } else if captureErr == nil {
                record.Outcome = serviceOutcomePartial
                record.Error = fmt.Sprintf("USN capture health query: %v", queryErr)
            }
            if err := appendRecord(record); err != nil {
                return fmt.Errorf("persist USN raw capture runtime result: %w", err)
            }
            lastReport = now
            capturedSinceReport = 0
        }
        if captureErr != nil {
            // Preserve both queue cursors; never advance or silently rebase.
            return fmt.Errorf("raw USN capture failed closed: %w", captureErr)
        }
        if saturated {
            // There may still be unconsumed NTFS history; keep draining now.
            continue
        }
        select {
        case <-ctx.Done():
            return nil
        case <-ticker.C:
        }
    }
}
