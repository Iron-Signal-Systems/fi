// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"errors"
	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
	"path/filepath"
	"testing"
	"time"
)

func testUSNCapture(t *testing.T) (*usncapture.Store, records.USNJournalState) {
	t.Helper()
	volume := records.VolumeIdentity{MethodVersion: "ntfs-volume/1", VolumeGUID: `\\?\Volume{11111111-2222-3333-4444-555555555555}\`, VolumeSerial: "3"}
	anchor := usncapture.Cursor{Version: usncapture.SchemaVersion, ScopeID: "root-test", JournalID: "20", VolumeIdentity: volume, NextUSN: "100"}
	dir := filepath.Join(t.TempDir(), "capture")
	if err := usncapture.Initialize(dir, anchor); err != nil {
		t.Fatal(err)
	}
	s, err := usncapture.Open(dir, usncapture.DefaultMaxPendingBytes)
	if err != nil {
		t.Fatal(err)
	}
	state := records.USNJournalState{
		ObservedAt: time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"), CollectionMethod: "WindowsNTFSUSNJournalV0",
		ScopeID: "root-test", VolumeIdentity: volume, JournalID: "20", FirstUSN: "50", NextUSN: "200", LowestValidUSN: "0", MaxUSN: "999999", MaximumSize: "4294967296", AllocationDelta: "1073741824",
	}
	return s, state
}

func TestCaptureAdapterDoesNotAdvanceProcessingCursor(t *testing.T) {
	s, state := testUSNCapture(t)
	calls := 0
	changed, err := captureUSNOnceWithReaders(context.Background(), "root-test", `F:\Governed`, s,
		func(context.Context, string, string) (records.USNJournalState, error) { return state, nil },
		func(_ context.Context, scope, root, start string) (records.USNReadBatch, error) {
			calls++
			if start != "100" {
				t.Fatalf("wrong source start %q", start)
			}
			return records.USNReadBatch{ObservedAt: state.ObservedAt, CollectionMethod: state.CollectionMethod, ScopeID: scope, VolumeIdentity: state.VolumeIdentity, JournalID: state.JournalID, StartUSN: start, NextUSN: "150"}, nil
		},
	)
	if err != nil || !changed || calls != 1 {
		t.Fatalf("capture failed: %v %t %d", err, changed, calls)
	}
	if s.CaptureCursor().NextUSN != "150" || s.ProcessingCursor().NextUSN != "100" {
		t.Fatal("captured lane advanced processing checkpoint")
	}
}

func TestCaptureAdapterFailsClosedOnJournalRollover(t *testing.T) {
	s, state := testUSNCapture(t)
	state.FirstUSN = "120"
	called := false
	_, err := captureUSNOnceWithReaders(context.Background(), "root-test", `F:\Governed`, s,
		func(context.Context, string, string) (records.USNJournalState, error) { return state, nil },
		func(context.Context, string, string, string) (records.USNReadBatch, error) {
			called = true
			return records.USNReadBatch{}, nil
		},
	)
	if !errors.Is(err, usncapture.ErrGap) || called {
		t.Fatalf("journal overwrite not detected: %v, read=%t", err, called)
	}
}

func TestCaptureAdapterRejectsChangedJournalIdentity(t *testing.T) {
	s, state := testUSNCapture(t)
	state.JournalID = "21"
	_, err := captureUSNOnceWithReaders(context.Background(), "root-test", `F:\Governed`, s,
		func(context.Context, string, string) (records.USNJournalState, error) { return state, nil },
		func(context.Context, string, string, string) (records.USNReadBatch, error) {
			t.Fatal("read after journal change")
			return records.USNReadBatch{}, nil
		},
	)
	if !errors.Is(err, usncapture.ErrConflict) {
		t.Fatalf("expected journal identity conflict: %v", err)
	}
}
