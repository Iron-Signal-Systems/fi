// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestConcurrentSourcesBoundedExecution(t *testing.T) {
	ctx, cancel := context.WithTimeout(
		context.Background(), 5*time.Second,
	)
	defer cancel()

	ready := make(chan string, 3)
	active := make(chan string, 3)
	release := make(chan struct{})

	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()

	runner := func(
		ctx context.Context,
		cfg workerConfig,
		_ string,
	) error {
		if cfg.Workers != 1 ||
			cfg.IngestSlots == nil ||
			len(cfg.SourceIDs) != 1 ||
			cfg.SourceIDs[0] != cfg.SourceID {
			return errors.New("invalid per-source worker state")
		}

		select {
		case ready <- cfg.SourceID:
		case <-ctx.Done():
			return ctx.Err()
		}

		select {
		case cfg.IngestSlots <- struct{}{}:
			defer func() { <-cfg.IngestSlots }()
		case <-ctx.Done():
			return ctx.Err()
		}

		select {
		case active <- cfg.SourceID:
		case <-ctx.Done():
			return ctx.Err()
		}

		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	done := make(chan error, 1)

	go func() {
		done <- runConcurrentSourceSessions(
			ctx,
			workerConfig{
				Workers: 2,
				Once:    true,
				SourceIDs: []string{
					"source-a",
					"source-b",
					"source-c",
				},
			},
			"test-singleton",
			runner,
		)
	}()

	// Prove all three source runners have started.
	for i := 0; i < 3; i++ {
		select {
		case <-ready:
		case <-ctx.Done():
			t.Fatal("not all source runners started")
		}
	}

	// Only two may enter the simulated generation operation.
	seen := make(map[string]bool)

	for i := 0; i < 2; i++ {
		select {
		case source := <-active:
			if seen[source] {
				t.Fatalf("duplicate active source: %s", source)
			}
			seen[source] = true
		case <-ctx.Done():
			t.Fatal("two worker slots were not occupied")
		}
	}

	select {
	case source := <-active:
		t.Fatalf(
			"concurrency limit exceeded by %s",
			source,
		)
	case <-time.After(200 * time.Millisecond):
	}

	// Releasing the slots must let the third source progress.
	close(release)

	select {
	case source := <-active:
		if seen[source] {
			t.Fatalf("source entered twice: %s", source)
		}
		seen[source] = true
	case <-ctx.Done():
		t.Fatal("waiting source never obtained a slot")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("supervisor returned error: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("supervisor did not finish")
	}

	if len(seen) != 3 {
		t.Fatalf("executed %d sources, want 3", len(seen))
	}
}
