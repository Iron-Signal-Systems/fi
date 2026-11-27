// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

func TestFIGenerationAdmissionLimits(t *testing.T) {
	cases := []struct {
		name         string
		limitRecords uint64
		limitBytes   uint64
		records      uint64
		bytes        uint64
		denied       bool
	}{
		{"unrestricted", 0, 0, 15140785, 65205192753, false},
		{"below_limits", 100, 1024, 99, 1023, false},
		{"exact_limits", 100, 1024, 100, 1024, false},
		{"record_exceeded", 100, 1024, 101, 1024, true},
		{"bytes_exceeded", 100, 1024, 100, 1025, true},
		{"both_exceeded", 100, 1024, 101, 1025, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := fiCheckGenerationAdmission(
				workerConfig{
					MaxGenerationRecords:   tc.limitRecords,
					MaxGenerationDataBytes: tc.limitBytes,
				},
				recordingest.RecordedReceiptCandidate{
					SourceID:     "test-source.iss.local",
					GenerationID: "test-generation",
					RecordCount:  tc.records,
					DataBytes:    tc.bytes,
				},
			)
			if (err != nil) != tc.denied {
				t.Fatalf("denied=%t err=%v", tc.denied, err)
			}
			if tc.denied && !strings.Contains(err.Error(), "remains pending") {
				t.Fatalf("missing pending custody guarantee: %v", err)
			}
		})
	}
}

func TestFIGenerationAdmissionBeforeAttempt(t *testing.T) {
	item := recordingest.ReconcilePlanItem{
		State: recordingest.ReconcileStatePending,
		Candidate: recordingest.RecordedReceiptCandidate{
			SourceID:     "test-source.iss.local",
			GenerationID: "oversized-generation",
			RecordCount:  15140785,
			DataBytes:    65205192753,
		},
	}

	// A nil connection is intentional. Admission must happen
	// before any attempt journal or database interaction.
	result, err := attemptGeneration(
		context.Background(),
		workerConfig{
			MaxGenerationRecords:   100000,
			MaxGenerationDataBytes: 268435456,
		},
		postgresConnection{},
		item,
	)

	if err == nil || !strings.Contains(err.Error(), "ADMISSION BLOCKED") {
		t.Fatalf("admission did not fail closed: %v", err)
	}
	if result.AttemptID != "" {
		t.Fatalf("attempt unexpectedly started: %q", result.AttemptID)
	}
}
