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

func TestDeploymentConfigPreservesApprovedUSNReadBufferSizes(t *testing.T) {
	for _, size := range []int{1, 2, 4, 8, 16, 32, 64} {
		t.Run(string(rune('0'+size)), func(t *testing.T) {
			report := deploymentConfigTestReport()
			inputs := deploymentConfigTestInputs()
			inputs.USNReadBufferMiB = size

			manual, err := BuildManualDeploymentConfigProposal(report, inputs)
			if err != nil {
				t.Fatal(err)
			}

			parsed, err := config.Parse(strings.NewReader(string(manual.Normalized)))
			if err != nil {
				t.Fatal(err)
			}
			if got := parsed.Collector.USNReadBufferMiB; got != size {
				t.Fatalf("normalized USN read size=%d, want %d", got, size)
			}
			path := filepath.Join(t.TempDir(), "fi.conf")
			if err := os.WriteFile(path, manual.Normalized, 0o600); err != nil {
				t.Fatal(err)
			}
			fileProposal, err := LoadDeploymentConfigProposal(report, path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.EqualFold(fileProposal.NormalizedSHA256, manual.NormalizedSHA256) || string(fileProposal.Normalized) != string(manual.Normalized) {
				t.Fatal("approved file-sourced USN read size did not round-trip exactly")
			}
		})
	}
}

func TestDeploymentConfigRejectsOutOfRangeUSNReadBuffer(t *testing.T) {
	report := deploymentConfigTestReport()
	inputs := deploymentConfigTestInputs()
	for _, size := range []int{-1, 65} {
		inputs.USNReadBufferMiB = size
		if _, err := BuildManualDeploymentConfigProposal(report, inputs); err == nil {
			t.Fatalf("USN read size %d unexpectedly accepted", size)
		}
	}
}
