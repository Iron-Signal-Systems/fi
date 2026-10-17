// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"context"
	"errors"
	"fmt"
)

// runConcurrentSourceSessions retains one process-level lock while giving
// each source an independent database session, repair state, retry state,
// and execution loop. IngestSlots bounds concurrent generation operations.
func runConcurrentSourceSessions(
	ctx context.Context,
	config workerConfig,
	lockPath string,
	run func(context.Context, workerConfig, string) error,
) error {
	if run == nil {
		return errors.New("FI source runner is required")
	}
	if config.MaxAttempts != 0 {
		return errors.New(
			"concurrent source workers do not support global max-attempts",
		)
	}
	if config.Workers < 1 || config.Workers > 32 {
		return errors.New("invalid FI source worker concurrency")
	}
	if len(config.SourceIDs) == 0 {
		return errors.New("no enabled FI sources")
	}

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	slots := make(chan struct{}, config.Workers)

	type result struct {
		sourceID string
		err      error
	}

	results := make(chan result, len(config.SourceIDs))

	for _, id := range config.SourceIDs {
		sourceID := id
		sourceConfig := config
		sourceConfig.SourceID = sourceID
		sourceConfig.SourceIDs = []string{sourceID}
		sourceConfig.Workers = 1
		sourceConfig.IngestSlots = slots

		go func() {
			results <- result{
				sourceID: sourceID,
				err:      run(workerCtx, sourceConfig, lockPath),
			}
		}()
	}

	var firstErr error

	for range config.SourceIDs {
		outcome := <-results

		if outcome.err != nil &&
			!errors.Is(outcome.err, context.Canceled) {
			if firstErr == nil {
				firstErr = fmt.Errorf(
					"source %s: %w",
					outcome.sourceID,
					outcome.err,
				)
				cancel()
			}
		} else if outcome.err == nil &&
			!config.Once &&
			ctx.Err() == nil &&
			firstErr == nil {
			firstErr = fmt.Errorf(
				"source %s worker exited unexpectedly",
				outcome.sourceID,
			)
			cancel()
		}
	}

	if firstErr != nil {
		return firstErr
	}
	return ctx.Err()
}
