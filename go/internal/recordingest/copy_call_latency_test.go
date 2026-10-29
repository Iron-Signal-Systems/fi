// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"strings"
	"testing"
	"time"
)

// These tests use exact durations to avoid scheduler-sensitive timing tests.
func TestCopyCallLatencyEmpty(t *testing.T) {
	var latency copyCallLatency
	want := "calls=0,min=0s,max=0s,ge_1s=0,ge_5s=0"
	if got := latency.String(); got != want {
		t.Fatalf("empty latency: got %q want %q", got, want)
	}
}

func TestCopyCallLatencyThresholdsAndExtrema(t *testing.T) {
	var latency copyCallLatency
	for _, duration := range []time.Duration{
		750 * time.Millisecond,
		time.Second,
		5 * time.Second,
		10 * time.Millisecond,
		6 * time.Second,
	} {
		latency.observe(duration)
	}
	if latency.Calls != 5 ||
		latency.Min != 10*time.Millisecond ||
		latency.Max != 6*time.Second ||
		latency.AtLeastOneSecond != 3 ||
		latency.AtLeastFiveSeconds != 2 {
		t.Fatalf("incorrect latency counters: %+v", latency)
	}
	for _, token := range []string{
		"calls=5", "min=10ms", "max=6s", "ge_1s=3", "ge_5s=2",
	} {
		if !strings.Contains(latency.String(), token) {
			t.Fatalf("missing %q in %q", token, latency.String())
		}
	}
}

func TestCopyCallLatencyZeroAndNegative(t *testing.T) {
	var latency copyCallLatency
	latency.observe(-time.Millisecond)
	latency.observe(0)
	if latency.Calls != 2 || latency.Min != 0 || latency.Max != 0 ||
		latency.AtLeastOneSecond != 0 || latency.AtLeastFiveSeconds != 0 {
		t.Fatalf("invalid duration handling: %+v", latency)
	}
}
