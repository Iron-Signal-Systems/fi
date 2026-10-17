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

func TestConcurrentSourcesIndependentExecution(t *testing.T) {
	ctx, cancel := context.WithTimeout(
		context.Background(), 5*time.Second,
	)
	defer cancel()

	started := make(chan string, 2)
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
		if len(cfg.SourceIDs) != 1 ||
			cfg.SourceIDs[0] != cfg.SourceID ||
			cfg.IngestSlots == nil {
			return errors.New("source isolation invalid")
		}

		select {
		case cfg.IngestSlots <- struct{}{}:
			defer func() { <-cfg.IngestSlots }()
		case <-ctx.Done():
			return ctx.Err()
		}

		select {
		case started <- cfg.SourceID:
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
					"iss-fs-22a.iss.local",
					"iss-fs-22b.iss.local",
				},
			},
			"test-lock",
			runner,
		)
	}()

	seen := make(map[string]bool)

	for len(seen) < 2 {
		select {
		case source := <-started:
			if seen[source] {
				t.Fatalf("duplicate source: %s", source)
			}
			seen[source] = true

		case <-ctx.Done():
			t.Fatal("both sources did not run concurrently")
		}
	}

	close(release)

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("supervisor failed to finish")
	}
}

func TestConcurrentSourcesPropagateFatalError(t *testing.T) {
	ctx, cancel := context.WithTimeout(
		context.Background(), 5*time.Second,
	)
	defer cancel()

	injected := errors.New("injected failure")

	err := runConcurrentSourceSessions(
		ctx,
		workerConfig{
			Workers:   2,
			SourceIDs: []string{"source-a", "source-b"},
		},
		"test-lock",
		func(
			ctx context.Context,
			cfg workerConfig,
			_ string,
		) error {
			if cfg.SourceID == "source-a" {
				return injected
			}
			<-ctx.Done()
			return ctx.Err()
		},
	)

	if !errors.Is(err, injected) {
		t.Fatalf("failure not propagated: %v", err)
	}
}
