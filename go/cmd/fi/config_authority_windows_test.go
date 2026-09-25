// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
)

func TestResolveCollectorIntervalsUsesConfiguredValuesWithoutOverride(t *testing.T) {
	value := collectorAuthorityTestConfig(false, false)

	var warning bytes.Buffer

	collection, supporting, err := resolveCollectorIntervals(
		value,
		"",
		"",
		&warning,
	)
	if err != nil {
		t.Fatal(err)
	}

	if collection != time.Minute {
		t.Fatalf("collection = %s, want 1m", collection)
	}
	if supporting != 30*time.Minute {
		t.Fatalf("supporting refresh = %s, want 30m", supporting)
	}
	if warning.Len() != 0 {
		t.Fatalf("unexpected warning = %q", warning.String())
	}
}

func TestResolveCollectorIntervalsRejectsOverrideWhenTroubleshootingDisabled(t *testing.T) {
	value := collectorAuthorityTestConfig(false, true)

	_, _, err := resolveCollectorIntervals(
		value,
		"2m",
		"",
		nil,
	)
	if err == nil {
		t.Fatal("resolveCollectorIntervals() error = nil, want override rejection")
	}
	if !strings.Contains(
		err.Error(),
		"manual FI collector interval overrides are disabled by configuration",
	) {
		t.Fatalf("error = %v", err)
	}
}

func TestResolveCollectorIntervalsRejectsOverrideWithoutCollectorAuthority(t *testing.T) {
	value := collectorAuthorityTestConfig(true, false)

	_, _, err := resolveCollectorIntervals(
		value,
		"2m",
		"",
		nil,
	)
	if err == nil {
		t.Fatal("resolveCollectorIntervals() error = nil, want override rejection")
	}
	if !strings.Contains(
		err.Error(),
		"manual FI collector interval overrides are disabled by configuration",
	) {
		t.Fatalf("error = %v", err)
	}
}

func TestResolveCollectorIntervalsAppliesAuthorizedOverrides(t *testing.T) {
	value := collectorAuthorityTestConfig(true, true)

	var warning bytes.Buffer

	collection, supporting, err := resolveCollectorIntervals(
		value,
		"2m",
		"45m",
		&warning,
	)
	if err != nil {
		t.Fatal(err)
	}

	if collection != 2*time.Minute {
		t.Fatalf("collection = %s, want 2m", collection)
	}
	if supporting != 45*time.Minute {
		t.Fatalf("supporting refresh = %s, want 45m", supporting)
	}

	got := warning.String()

	for _, expected := range []string{
		"WARNING:",
		"service-collection-every",
		"service-supporting-refresh-every",
	} {
		if !strings.Contains(got, expected) {
			t.Fatalf("warning %q does not contain %q", got, expected)
		}
	}

	// The warning identifies authority use without exposing supplied values.
	for _, prohibited := range []string{
		"2m",
		"45m",
	} {
		if strings.Contains(got, prohibited) {
			t.Fatalf("warning %q unexpectedly contains override value %q", got, prohibited)
		}
	}
}

func TestResolveCollectorIntervalsRejectsMalformedAuthorizedOverride(t *testing.T) {
	value := collectorAuthorityTestConfig(true, true)

	var warning bytes.Buffer

	_, _, err := resolveCollectorIntervals(
		value,
		"not-a-duration",
		"",
		&warning,
	)
	if err == nil {
		t.Fatal("resolveCollectorIntervals() error = nil, want duration rejection")
	}

	if warning.Len() != 0 {
		t.Fatalf(
			"warning emitted before override validation completed: %q",
			warning.String(),
		)
	}
}

func collectorAuthorityTestConfig(
	troubleshootEnabled bool,
	allowCollector bool,
) config.Config {
	var value config.Config

	value.Collector.CollectionEvery = time.Minute
	value.Collector.SupportingRefreshEvery = 30 * time.Minute
	value.Troubleshoot.Enabled = troubleshootEnabled
	value.Troubleshoot.AllowCollectorCLIOverride = allowCollector

	return value
}
