// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usn"
)

// captureUSNOnce is the capture-side adapter for the new two-cursor pipeline.
// It is deliberately not wired into the active service until processing-lane
// publication, migration, and installer acceptance have their own tests.
// No FI verified-spool checkpoint is moved by this function.
func captureUSNOnce(
	ctx context.Context,
	scopeID, governedRoot string,
	store *usncapture.Store,
) (bool, error) {
	return captureUSNOnceWithReaders(ctx, scopeID, governedRoot, store, usn.QueryJournal, usn.ReadJournal)
}

type captureQuery func(context.Context, string, string) (records.USNJournalState, error)
type captureRead func(context.Context, string, string, string) (records.USNReadBatch, error)

func captureUSNOnceWithReaders(
	ctx context.Context, scopeID, governedRoot string, store *usncapture.Store,
	query captureQuery, read captureRead,
) (bool, error) {
	if ctx == nil {
		return false, errors.New("USN capture context required")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if store == nil || query == nil || read == nil {
		return false, errors.New("capture dependencies required")
	}
	cursor := store.CaptureCursor()
	if cursor.ScopeID != scopeID {
		return false, fmt.Errorf("%w: scope", usncapture.ErrConflict)
	}
	state, err := query(ctx, scopeID, governedRoot)
	if err != nil {
		return false, err
	}
	if err := records.ValidateUSNJournalState(state); err != nil {
		return false, err
	}
	if cursor.JournalID != state.JournalID || !reflect.DeepEqual(cursor.VolumeIdentity, state.VolumeIdentity) {
		return false, fmt.Errorf("%w: journal or volume changed", usncapture.ErrConflict)
	}
	next, err := strconv.ParseUint(cursor.NextUSN, 10, 64)
	if err != nil {
		return false, err
	}
	first, err := strconv.ParseUint(state.FirstUSN, 10, 64)
	if err != nil {
		return false, err
	}
	lowest, err := strconv.ParseUint(state.LowestValidUSN, 10, 64)
	if err != nil {
		return false, err
	}
	head, err := strconv.ParseUint(state.NextUSN, 10, 64)
	if err != nil {
		return false, err
	}
	if next < first || (lowest != 0 && next < lowest) {
		return false, fmt.Errorf("%w: checkpoint aged out before capture (next=%d first=%d lowest=%d)", usncapture.ErrGap, next, first, lowest)
	}
	if next > head {
		return false, fmt.Errorf("%w: capture cursor ahead of journal", usncapture.ErrConflict)
	}
	if next == head {
		return false, nil
	}
	batch, err := read(ctx, scopeID, governedRoot, cursor.NextUSN)
	if err != nil {
		return false, err
	}
	if batch.NextUSN == cursor.NextUSN {
		return false, nil
	}
	if err := store.Append(batch); err != nil {
		return false, err
	}
	return true, nil
}
