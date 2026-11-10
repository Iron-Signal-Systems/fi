// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package volumecustody

import (
	"context"
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumeepoch"
)

// ErrUnconfiguredPass is returned before I/O if the per-volume coordinator
// lacks a required dependency. In particular there is no unlocked fallback.
var (
	ErrUnconfiguredPass = errors.New("FI volume-first one-pass source coordination is not configured")
	ErrVolumeCheckpointConflict = errors.New("FI volume checkpoint changed during bounded source capture")
)

// LeaseProvider MUST provide exclusive source+checkpoint ownership for one
// enrolled volume, across processes, from acquisition until Release returns.
// Lock is never authorization to open a journal: the native broker and
// installed grant must independently establish that authority.
type LeaseProvider interface {
	Acquire(context.Context, string) (Lease, error)
}

type Lease interface {
	Release() error
}

// CheckpointStore is a separately owned durable state dependency. Commit MUST
// enforce a persistent atomic compare-and-swap against the complete expected
// checkpoint (not just NextUSN), reject stale state, and persist a fully
// verified replacement before reporting success. The coordinator alone
// cannot prove an implementation satisfies those guarantees.
type CheckpointStore interface {
	Load(context.Context, string) (volumeepoch.Checkpoint, error)
	Commit(context.Context, volumeepoch.Checkpoint, volumeepoch.Checkpoint) error
}

// NativeWindowSource is the future trust-bound native FIUSNReader client.
// ReadBounded MUST return every record in its bounded journal read, with the
// actual observed volume/journal state and the final cursor. QueryJournal
// must re-observe the SAME enrolled volume; neither path may be selected by
// user-controlled device names or arbitrary filesystem paths.
//
// An injected stub is test-only. These contracts are not a service identity
// proof or installed-grant verification.
type NativeWindowSource interface {
	ReadBounded(context.Context, string, string, uint32) (Window, volumeepoch.Journal, error)
	QueryJournal(context.Context, string) (volumeepoch.Journal, error)
}

// WindowPublisher publishes all source facts PLUS the terminal boundary as
// one complete verified FI spool batch. It must not return a manifest path
// until publication and durability are complete. Errors must not silently
// delete or replace an in-doubt published batch.
type WindowPublisher interface {
	PublishWindow(context.Context, Window) (manifestPath string, err error)
}

// PassDependencies is constructed by a future trusted runtime, never from
// unverified configuration. No Windows native implementations or service
// startup are connected to this coordinator yet.
type PassDependencies struct {
	Lease     LeaseProvider
	Store     CheckpointStore
	Source    NativeWindowSource
	Publisher WindowPublisher
	SpoolDir  string
}

// PassResult preserves source custody evidence even on failure. Published
// does NOT mean cursor committed. CommitAttempted and !CheckpointCommitted
// represent an IN-DOUBT durable CAS, not proof of unchanged checkpoint.
// Such a failure requires reloading protected checkpoint state before retry;
// never delete or retire the already published spool evidence.
type PassResult struct {
	EnrollmentID        string
	ManifestPath        string
	Published           bool
	Candidate           *volumeepoch.Checkpoint
	CommitAttempted     bool
	CheckpointCommitted bool
}

// ProcessOneWindow coordinates exactly one bounded per-volume source pass.
// It does not initialize an epoch or recover a gap; both require separate,
// explicit baseline/discontinuity evidence before any source checkpoint exists.
//
// The correct sequence is lease -> checkpoint -> native read -> source-window
// validation -> complete publication -> native journal rediscovery -> manifest
// verification -> saved-state recheck -> atomic checkpoint CAS -> release.
// All failures BEFORE Commit leave checkpoint persistence untouched; an
// error FROM Commit leaves its durable outcome IN DOUBT. Published artifacts
// must remain available for manual replay/reconciliation in either case.
// A caller-supplied fake Source/Store/Lease is NOT production authorization.
func ProcessOneWindow(
	ctx context.Context,
	enrollmentID string,
	deps PassDependencies,
) (result PassResult, returnErr error) {
	if ctx == nil || !validPassEnrollment(enrollmentID) ||
		deps.Lease == nil || deps.Store == nil ||
		deps.Source == nil || deps.Publisher == nil || deps.SpoolDir == "" {
		return PassResult{}, ErrUnconfiguredPass
	}
	if err := ctx.Err(); err != nil {
		return PassResult{}, err
	}
	result.EnrollmentID = enrollmentID

	lease, err := deps.Lease.Acquire(ctx, enrollmentID)
	if err != nil {
		return result, fmt.Errorf("acquire exclusive FI enrolled-volume lease: %w", err)
	}
	if lease == nil {
		return result, fmt.Errorf("%w: lease provider returned no lease", ErrUnconfiguredPass)
	}
	defer func() {
		if err := lease.Release(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("release FI enrolled-volume lease: %w", err))
		}
	}()

	saved, err := deps.Store.Load(ctx, enrollmentID)
	if err != nil {
		return result, fmt.Errorf("load durable FI volume checkpoint: %w", err)
	}
	// Discover the actual enrolled journal BEFORE requesting a bounded read.
	// Besides detecting a gap, Assess validates every persisted checkpoint
	// field (including exact canonical unsigned NextUSN) and the actual journal
	// identity. Untrusted persistent bytes never reach the privileged reader.
	before, err := deps.Source.QueryJournal(ctx, enrollmentID)
	if err != nil {
		return result, fmt.Errorf("query enrolled-volume journal before read: %w", err)
	}
	assessment, err := volumeepoch.Assess(enrollmentID, &saved, before)
	if err != nil {
		return result, fmt.Errorf("%w: invalid checkpoint/journal: %v", ErrUnsafeWindow, err)
	}
	if assessment.State != volumeepoch.Continuous {
		return result, fmt.Errorf("%w: cannot start bounded read from %s/%s", ErrUnsafeWindow, assessment.State, assessment.Reason)
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	window, readJournal, err := deps.Source.ReadBounded(
		ctx, enrollmentID, saved.NextUSN, maxWindowChanges,
	)
	if err != nil {
		return result, fmt.Errorf("read bounded enrolled-volume journal: %w", err)
	}
	// Validate all expected source facts before any spool writes.
	if err := validateWindow(saved, readJournal, window); err != nil {
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	// Snapshot the native read before presenting a mutable window to the
	// external publisher. The later byte-for-byte verifier MUST use the
	// untouched source snapshot, never a caller-modified publisher argument.
	captured := Window{
		Boundary: window.Boundary,
		Changes:  append([]MinimalChange(nil), window.Changes...),
	}
	publishInput := Window{
		Boundary: captured.Boundary,
		Changes:  append([]MinimalChange(nil), captured.Changes...),
	}
	manifest, err := deps.Publisher.PublishWindow(ctx, publishInput)
	if err != nil {
		return result, fmt.Errorf("publish complete FI source window: %w", err)
	}
	if manifest == "" {
		return result, fmt.Errorf("%w: publisher did not return a manifest", ErrUnverifiedCustody)
	}
	result.ManifestPath = manifest
	result.Published = true
	if err := ctx.Err(); err != nil {
		return result, err
	}
	// A fresh journal state is required after publication: a changed journal
	// or aged-out/invalid replay bound cannot quietly advance the cursor.
	current, err := deps.Source.QueryJournal(ctx, enrollmentID)
	if err != nil {
		return result, fmt.Errorf("re-query enrolled-volume journal after publication: %w", err)
	}
	candidate, err := ProposeAfterPublishedWindow(
		saved, current, captured, deps.SpoolDir, manifest,
	)
	if err != nil {
		return result, err
	}
	result.Candidate = &candidate
	if err := ctx.Err(); err != nil {
		return result, err
	}
	// Prevent a stale stored checkpoint from being silently overwritten by
	// another writer. The final Commit MUST still perform its own atomic CAS.
	fresh, err := deps.Store.Load(ctx, enrollmentID)
	if err != nil {
		return result, fmt.Errorf("re-read volume checkpoint before compare-and-swap: %w", err)
	}
	if fresh != saved {
		return result, ErrVolumeCheckpointConflict
	}
	result.CommitAttempted = true
	if err := deps.Store.Commit(ctx, saved, candidate); err != nil {
		return result, fmt.Errorf("commit verified volume cursor by durable compare-and-swap (outcome in doubt; inspect protected state before retry): %w", err)
	}
	result.CheckpointCommitted = true
	return result, nil
}

// validPassEnrollment is intentionally checked before invoking the external
// lease provider. It matches the canonical volumeepoch enrollment namespace,
// preventing a path-like name from ever becoming a lock or checkpoint key.
func validPassEnrollment(value string) bool {
	if len(value) == 0 || len(value) > 64 ||
		value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for i := 1; i < len(value); i++ {
		c := value[i]
		if !((c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
