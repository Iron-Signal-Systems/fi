// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package main

import (
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportreceiver"
)

func TestGenerationRuntimeOptionsRequireExplicitEnablement(
	t *testing.T,
) {
	if err := (generationRuntimeOptions{}).validate(); err != nil {
		t.Fatalf("disabled empty generation options rejected: %v", err)
	}

	options := generationRuntimeOptions{
		CustodyRoot: "/var/lib/fi/generation-custody",
	}

	err := options.validate()
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"require -generation-enable",
		) {
		t.Fatalf(
			"configured disabled generation options error = %v, want explicit enablement rejection",
			err,
		)
	}
}

func TestGenerationRuntimeOptionsRequireCompleteEnabledConfiguration(
	t *testing.T,
) {
	options := generationRuntimeOptions{
		Enabled: true,
	}

	err := options.validate()
	if err == nil ||
		!strings.Contains(
			err.Error(),
			"requires generation custody/recorded roots",
		) {
		t.Fatalf(
			"incomplete enabled generation options error = %v",
			err,
		)
	}
}

func TestGenerationRuntimeOptionsApplyListenerConfiguration(
	t *testing.T,
) {
	options := generationRuntimeOptions{
		CustodyRoot:       "/var/lib/fi/generation-custody",
		Enabled:           true,
		MaxCanonicalBytes: 64 << 30,
		MaxEncodedBytes:   16 << 30,
		MaxManifestBytes:  1 << 20,
		RecordedRoot:      "/var/lib/fi/generation-recorded",
	}

	if err := options.validate(); err != nil {
		t.Fatal(err)
	}

	var config transportreceiver.Config
	options.apply(&config)

	if !config.GenerationEnabled ||
		config.GenerationCustodyRoot != options.CustodyRoot ||
		config.GenerationRecordedRoot != options.RecordedRoot ||
		config.GenerationMaxCanonicalBytes != options.MaxCanonicalBytes ||
		config.GenerationMaxEncodedBytes != options.MaxEncodedBytes ||
		config.GenerationMaxManifestBytes != options.MaxManifestBytes {
		t.Fatalf(
			"applied generation config = %#v, want options %#v",
			config,
			options,
		)
	}
}
