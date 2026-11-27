// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

// newSourceBatchBulkTestBatch supplies one valid immutable-batch identity.
func newSourceBatchBulkTestBatch(id string) PreparedBatch {
	const instant = "2026-10-23T08:00:00.000000000Z"
	return PreparedBatch{
		BatchID:              id,
		ManifestArtifactName: "batch-" + id + ".manifest.json",
		DataArtifactName:     "batch-" + id + ".jsonl",
		ManifestBytes:        512,
		ManifestSHA256:       hex.EncodeToString(bytes.Repeat([]byte{0x12}, 32)),
		Manifest: spool.Manifest{
			Version:         spool.ManifestVersion,
			BatchID:         id,
			TargetBatchSize: 1024,
			RecordCount:     1,
			DataBytes:       128,
			DataSHA256:      hex.EncodeToString(bytes.Repeat([]byte{0x34}, 32)),
			DataFile:        "batch-" + id + ".jsonl",
			Collector: spool.CollectorIdentity{
				ExecutablePath:   `C:\FI\fi-collector.exe`,
				ExecutableSHA256: hex.EncodeToString(bytes.Repeat([]byte{0x56}, 32)),
			},
			CreatedAt:   instant,
			CompletedAt: instant,
		},
	}
}

func TestPrepareSourceBatchBulkRowPreservesMetadata(t *testing.T) {
	row, err := prepareSourceBatchBulkRow(44, newSourceBatchBulkTestBatch("b-00001"))
	if err != nil {
		t.Fatal(err)
	}
	if len(row) != 16 {
		t.Fatalf("column count = %d, want 16", len(row))
	}
	if row[0] != int64(44) || row[4] != "b-00001" || row[6] != int64(1) || row[7] != int64(128) || row[14] != int64(512) {
		t.Fatalf("metadata fields changed: %#v", row)
	}
	for _, index := range []int{8, 11, 15} {
		if hash, ok := row[index].([]byte); !ok || len(hash) != 32 {
			t.Fatalf("column %d: digest type/length changed", index)
		}
	}
	for _, index := range []int{12, 13} {
		if date, ok := row[index].(time.Time); !ok || date.IsZero() || date.Location() != time.UTC {
			t.Fatalf("column %d: timestamp invalid: %v", index, row[index])
		}
	}
}

func TestPrepareSourceBatchBulkRowRejectsBadFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*PreparedBatch)
	}{
		{"data hash", func(b *PreparedBatch) { b.Manifest.DataSHA256 = "bad" }},
		{"collector hash", func(b *PreparedBatch) { b.Manifest.Collector.ExecutableSHA256 = "bad" }},
		{"manifest hash", func(b *PreparedBatch) { b.ManifestSHA256 = "bad" }},
		{"created_at", func(b *PreparedBatch) { b.Manifest.CreatedAt = "not-a-date" }},
		{"completed_at", func(b *PreparedBatch) { b.Manifest.CompletedAt = "not-a-date" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			batch := newSourceBatchBulkTestBatch("b-00001")
			test.mutate(&batch)
			if _, err := prepareSourceBatchBulkRow(44, batch); err == nil {
				t.Fatal("invalid batch accepted")
			}
		})
	}
}

func TestCopySourceBatchesRejectsIncompleteInputs(t *testing.T) {
	if _, err := copySourceBatches(context.Background(), nil, 44,
		[]PreparedBatch{newSourceBatchBulkTestBatch("b-00001")},
		&sourceBatchBulkProfile{}); err == nil {
		t.Fatal("nil transaction accepted")
	}
}
