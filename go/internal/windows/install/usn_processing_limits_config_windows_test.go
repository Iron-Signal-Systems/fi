// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"strings"
	"testing"
)

func TestDeploymentConfigCarriesProcessingBoundsAndComments(t *testing.T) {
	report := deploymentConfigTestReport()
	inputs := deploymentConfigTestInputs()
	inputs.USNProcessingChunkObjects = 512
	inputs.USNProcessingMaxInflight = 16
	proposal, err := BuildManualDeploymentConfigProposal(report, inputs)
	if err != nil {
		t.Fatal(err)
	}
	contents := string(proposal.Normalized)
	for _, text := range []string{
		"Minimum: 1; maximum: 64", "Minimum: 1; maximum: 16",
		"Minimum: 64; maximum: 2048", "collector.usn_processing_chunk_objects = 512",
		"collector.usn_processing_max_inflight = 16",
	} {
		if !strings.Contains(contents, text) {
			t.Fatalf("missing generated config contract: %s", text)
		}
	}
	parsed, err := config.Parse(strings.NewReader(contents))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Collector.USNProcessingChunkObjects != 512 || parsed.Collector.USNProcessingMaxInflight != 16 {
		t.Fatalf("lost processing bounds %+v", parsed.Collector)
	}
}
