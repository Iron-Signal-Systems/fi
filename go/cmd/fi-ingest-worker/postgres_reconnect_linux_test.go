// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPostgreSQLBackoffIsBoundedAndResettable(
	t *testing.T,
) {
	backoff, err := newPostgreSQLBackoff(
		time.Second,
		30*time.Second,
	)
	if err != nil {
		t.Fatal(err)
	}

	want := []time.Duration{
		time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		30 * time.Second,
		30 * time.Second,
	}

	for index, expected := range want {
		if got := backoff.Next(); got != expected {
			t.Fatalf(
				"Next[%d] = %s, want %s",
				index,
				got,
				expected,
			)
		}
	}

	backoff.Reset()
	if got := backoff.Next(); got != time.Second {
		t.Fatalf(
			"Next after Reset = %s, want 1s",
			got,
		)
	}
}

func TestPostgreSQLBackoffRejectsInvalidBounds(
	t *testing.T,
) {
	if _, err := newPostgreSQLBackoff(
		0,
		time.Second,
	); err == nil {
		t.Fatal("zero initial retry interval was accepted")
	}

	if _, err := newPostgreSQLBackoff(
		2*time.Second,
		time.Second,
	); err == nil {
		t.Fatal("maximum below initial retry interval was accepted")
	}
}

func TestWaitPostgreSQLRetryHonorsCancellation(
	t *testing.T,
) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := waitPostgreSQLRetry(ctx, time.Hour)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf(
			"waitPostgreSQLRetry() error = %v, want context.Canceled",
			err,
		)
	}
}
