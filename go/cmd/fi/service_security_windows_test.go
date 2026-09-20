// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeServiceWindowsSecuritySource struct {
	mu        sync.Mutex
	calls     int
	active    int
	maxActive int
	summaries []serviceWindowsSecurityCycleSummary
	err       error
}

func (source *fakeServiceWindowsSecuritySource) Collect(
	context.Context,
) (serviceWindowsSecurityCycleSummary, error) {
	source.mu.Lock()
	source.calls++
	source.active++
	if source.active > source.maxActive {
		source.maxActive = source.active
	}
	call := source.calls
	source.mu.Unlock()

	time.Sleep(5 * time.Millisecond)

	source.mu.Lock()
	source.active--
	defer source.mu.Unlock()

	if source.err != nil {
		return serviceWindowsSecurityCycleSummary{}, source.err
	}
	if call <= len(source.summaries) {
		return source.summaries[call-1], nil
	}
	return serviceWindowsSecurityCycleSummary{
		Status: configuredSecurityComplete,
	}, nil
}

func (source *fakeServiceWindowsSecuritySource) snapshot() (int, int) {
	source.mu.Lock()
	defer source.mu.Unlock()
	return source.calls, source.maxActive
}

func TestResolveServiceWindowsSecurityIntervalDefaultAndOverride(t *testing.T) {
	t.Setenv(serviceWindowsSecurityIntervalEnvironment, "")
	interval, err := resolveServiceWindowsSecurityInterval()
	if err != nil {
		t.Fatal(err)
	}
	if interval != time.Minute {
		t.Fatalf("default interval = %s, want 1m", interval)
	}

	t.Setenv(serviceWindowsSecurityIntervalEnvironment, "15s")
	interval, err = resolveServiceWindowsSecurityInterval()
	if err != nil {
		t.Fatal(err)
	}
	if interval != 15*time.Second {
		t.Fatalf("override interval = %s, want 15s", interval)
	}
	if got := currentServiceWindowsSecurityInterval(); got != "15s" {
		t.Fatalf("current interval = %q, want 15s", got)
	}
}

func TestRunServiceWindowsSecurityLoopStartsImmediatelyAndDrainsBacklog(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	source := &fakeServiceWindowsSecuritySource{
		summaries: []serviceWindowsSecurityCycleSummary{
			{Status: configuredSecurityComplete, MoreAvailable: true},
			{Status: configuredSecurityComplete, MoreAvailable: true},
			{Status: configuredSecurityComplete, MoreAvailable: false},
		},
	}

	records := make(chan serviceRuntimeRecord, 4)
	done := make(chan error, 1)
	var appendedMu sync.Mutex
	appended := 0
	go func() {
		done <- runServiceWindowsSecurityLoop(
			ctx,
			time.Hour,
			source,
			func(record serviceRuntimeRecord) error {
				records <- record

				appendedMu.Lock()
				appended++
				shouldCancel := appended == 3
				appendedMu.Unlock()

				if shouldCancel {
					cancel()
				}
				return nil
			},
		)
	}()

	for index := 0; index < 3; index++ {
		select {
		case record := <-records:
			if record.RecordKind != "WindowsSecurityCatchUp" {
				t.Fatalf("record kind = %q", record.RecordKind)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("Windows Security worker did not drain immediate backlog")
		}
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Windows Security worker did not stop after cancellation")
	}

	calls, maxActive := source.snapshot()
	if calls != 3 {
		t.Fatalf("collector calls = %d, want 3", calls)
	}
	if maxActive != 1 {
		t.Fatalf("collector overlap = %d, want 1", maxActive)
	}
}

func TestRunServiceWindowsSecurityLoopRejectsInvalidDependencies(t *testing.T) {
	source := &fakeServiceWindowsSecuritySource{}
	appendRecord := func(serviceRuntimeRecord) error { return nil }

	if err := runServiceWindowsSecurityLoop(
		context.Background(),
		0,
		source,
		appendRecord,
	); err == nil {
		t.Fatal("zero interval unexpectedly accepted")
	}

	if err := runServiceWindowsSecurityLoop(
		context.Background(),
		time.Minute,
		nil,
		appendRecord,
	); err == nil {
		t.Fatal("nil source unexpectedly accepted")
	}
}

func TestRunServiceWindowsSecurityLoopPropagatesCollectorError(t *testing.T) {
	expected := errors.New("synthetic Security collector failure")
	source := &fakeServiceWindowsSecuritySource{err: expected}

	err := runServiceWindowsSecurityLoop(
		context.Background(),
		time.Minute,
		source,
		func(serviceRuntimeRecord) error { return nil },
	)
	if !errors.Is(err, expected) {
		t.Fatalf("error = %v, want %v", err, expected)
	}
}
