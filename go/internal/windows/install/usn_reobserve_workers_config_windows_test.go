// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
)

func TestDeploymentConfigPreservesApprovedUSNReobserveWorkers(t *testing.T) {
	for _, count := range []int{1, 4, 8, 16} {
		report := deploymentConfigTestReport()
		inputs := deploymentConfigTestInputs()
		inputs.USNReobserveWorkers = count
		manual, err := BuildManualDeploymentConfigProposal(report, inputs)
		if err != nil {
			t.Fatalf("workers=%d: %v", count, err)
		}
		parsed, err := config.Parse(strings.NewReader(string(manual.Normalized)))
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Collector.USNReobserveWorkers != count {
			t.Fatalf("workers=%d parsed=%d", count, parsed.Collector.USNReobserveWorkers)
		}
		path := filepath.Join(t.TempDir(), "fi.conf")
		if err := os.WriteFile(path, manual.Normalized, 0o600); err != nil {
			t.Fatal(err)
		}
		fileProposal, err := LoadDeploymentConfigProposal(report, path)
		if err != nil {
			t.Fatal(err)
		}
		if fileProposal.NormalizedSHA256 != manual.NormalizedSHA256 || string(fileProposal.Normalized) != string(manual.Normalized) {
			t.Fatalf("workers=%d did not round-trip through Approved-2 config file", count)
		}
	}
}

func TestDeploymentConfigRejectsInvalidUSNReobserveWorkers(t *testing.T) {
	report := deploymentConfigTestReport()
	for _, count := range []int{-1, 17} {
		inputs := deploymentConfigTestInputs()
		inputs.USNReobserveWorkers = count
		if _, err := BuildManualDeploymentConfigProposal(report, inputs); err == nil {
			t.Fatalf("workers=%d unexpectedly accepted", count)
		}
	}
}
