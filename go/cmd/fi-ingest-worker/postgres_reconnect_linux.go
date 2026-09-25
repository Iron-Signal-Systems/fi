// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package main

import (
	"context"
	"errors"
	"time"
)

type postgreSQLBackoff struct {
	current time.Duration
	initial time.Duration
	maximum time.Duration
}

func newPostgreSQLBackoff(
	initial time.Duration,
	maximum time.Duration,
) (
	postgreSQLBackoff,
	error,
) {
	if initial <= 0 {
		return postgreSQLBackoff{},
			errors.New(
				"FI PostgreSQL retry initial interval must be greater than zero",
			)
	}
	if maximum < initial {
		return postgreSQLBackoff{},
			errors.New(
				"FI PostgreSQL retry maximum interval must be greater than or equal to the initial interval",
			)
	}

	return postgreSQLBackoff{
		current: initial,
		initial: initial,
		maximum: maximum,
	}, nil
}

func (backoff *postgreSQLBackoff) Next() time.Duration {
	if backoff == nil {
		return 0
	}

	delay := backoff.current
	if delay <= 0 {
		return 0
	}

	if backoff.current < backoff.maximum {
		if backoff.current > backoff.maximum/2 {
			backoff.current = backoff.maximum
		} else {
			backoff.current *= 2
			if backoff.current > backoff.maximum {
				backoff.current = backoff.maximum
			}
		}
	}

	return delay
}

func (backoff *postgreSQLBackoff) Reset() {
	if backoff == nil {
		return
	}
	backoff.current = backoff.initial
}

func waitPostgreSQLRetry(
	ctx context.Context,
	delay time.Duration,
) error {
	if ctx == nil {
		return errors.New(
			"FI PostgreSQL retry context is required",
		)
	}
	if delay <= 0 {
		return errors.New(
			"FI PostgreSQL retry delay must be greater than zero",
		)
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
