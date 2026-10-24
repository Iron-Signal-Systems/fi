// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func TestSecurityCoverageBulkRejectsInvalidInput(t *testing.T) {
	profile := &ingestStageProfile{}
	state := newSecurityCoverageBulkState(profile)
	current := records.WindowsSecurityCoverageObservation{
		ObservedAt:       time.Now().UTC().Format(time.RFC3339Nano),
		CollectionMethod: records.WindowsSecurityCollectionMethod,
		Status:           records.WindowsSecurityCoverageReady,
	}

	tests := []struct {
		name   string
		kind   string
		value  records.WindowsSecurityCoverageObservation
		bytes  int
		source int64
		want   string
	}{
		{"invalid-source", "WindowsSecurityCoverage", current, 50, 0, "incomplete"},
		{"invalid-kind", "WindowsSecurityEvent", current, 50, 1, "incomplete"},
		{"invalid-bytes", "WindowsSecurityCoverage", current, 0, 1, "incomplete"},
		{"missing-policies", "WindowsSecurityCoverage", current, 50, 1, "validate"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			prepared := SourceRecord{
				Record:      spool.Record{RecordKind: test.kind, Payload: payload},
				RecordBytes: test.bytes,
			}
			err = state.add(context.Background(), nil, test.source, prepared)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q rejection, got %v", test.want, err)
			}
			if len(state.pending) != 0 {
				t.Fatal("invalid record was buffered")
			}
		})
	}
}

func TestSecurityCoverageBulkEmptyFlush(t *testing.T) {
	state := newSecurityCoverageBulkState(&ingestStageProfile{})
	if err := state.flush(context.Background(), nil); err != nil {
		t.Fatalf("empty flush: %v", err)
	}
	if state.profile.CoverageBulk.Records != 0 || state.profile.CoverageBulk.Chunks != 0 {
		t.Fatalf("unexpected empty-flush counters: %+v", state.profile.CoverageBulk)
	}
}
