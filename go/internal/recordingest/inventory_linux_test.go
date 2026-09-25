// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package recordingest

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func TestInspectPreparedGenerationKinds(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "batch.jsonl")

	fileRecord := []byte("{\"version\":\"fi-spool-record/0.1\",\"record_kind\":\"FileObservation\",\"scope_id\":\"root-a\",\"written_at\":\"2026-09-20T08:00:00Z\",\"payload\":{}}\n")
	securityRecord := []byte("{\"version\":\"fi-spool-record/0.1\",\"record_kind\":\"WindowsSecurityEvent\",\"scope_id\":\"security\",\"written_at\":\"2026-09-20T08:00:01Z\",\"payload\":{}}\n")
	raw := append(append([]byte(nil), fileRecord...), securityRecord...)

	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	generation := &PreparedGeneration{
		Batches: []PreparedBatch{{
			BatchID:  "batch-test",
			DataPath: path,
			Manifest: spool.Manifest{
				DataBytes:   int64(len(raw)),
				RecordCount: 2,
			},
		}},
		Receipt: generationrecorder.RecordedReceipt{
			DataBytes:   uint64(len(raw)),
			RecordCount: 2,
		},
	}

	counts, records, bytes, err := InspectPreparedGenerationKinds(generation)
	if err != nil {
		t.Fatalf("InspectPreparedGenerationKinds() error = %v", err)
	}
	if records != 2 || bytes != uint64(len(raw)) {
		t.Fatalf("records=%d bytes=%d", records, bytes)
	}
	if counts["FileObservation"] != 1 || counts["WindowsSecurityEvent"] != 1 {
		t.Fatalf("counts=%v", counts)
	}
}

func TestMissingSupportedKinds(t *testing.T) {
	counts := map[string]uint64{"FileObservation": 1}
	missing := missingSupportedKinds(counts)
	if len(missing) != len(SupportedRecordKinds())-1 {
		t.Fatalf("missing=%d want=%d", len(missing), len(SupportedRecordKinds())-1)
	}
}
