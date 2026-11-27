// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestWriterFinalizesBeforeTargetByteOverflow(t *testing.T) {
	writer := newBytePolicyTestWriter(t)

	writer.targetBatchBytes = 700
	writer.maxBatchBytes = 1400
	writer.batchSize = 100

	payload := map[string]string{
		"value": strings.Repeat("x", 400),
	}

	if err := writer.Append("test", "scope", payload); err != nil {
		t.Fatal(err)
	}

	if len(writer.FinalizedBatches()) != 0 {
		t.Fatal("first record unexpectedly finalized")
	}

	if err := writer.Append("test", "scope", payload); err != nil {
		t.Fatal(err)
	}

	batches := writer.FinalizedBatches()
	if len(batches) != 1 {
		t.Fatalf(
			"finalized batches = %d, want 1 before Close",
			len(batches),
		)
	}

	if batches[0].Manifest.RecordCount != 1 {
		t.Fatalf(
			"first batch record count = %d, want 1",
			batches[0].Manifest.RecordCount,
		)
	}

	if batches[0].Manifest.DataBytes > writer.targetBatchBytes {
		t.Fatalf(
			"first batch bytes = %d, target = %d",
			batches[0].Manifest.DataBytes,
			writer.targetBatchBytes,
		)
	}

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	batches = writer.FinalizedBatches()
	if len(batches) != 2 {
		t.Fatalf(
			"finalized batches after Close = %d, want 2",
			len(batches),
		)
	}
}

func TestWriterStreamingManifestStillVerifiesIndependently(t *testing.T) {
	writer := newBytePolicyTestWriter(t)

	writer.targetBatchBytes = 1024 * 1024
	writer.maxBatchBytes = 2 * 1024 * 1024
	writer.batchSize = 100

	for i := 0; i < 3; i++ {
		if err := writer.Append(
			"test",
			"scope",
			map[string]int{"value": i},
		); err != nil {
			t.Fatal(err)
		}
	}

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	batches := writer.FinalizedBatches()
	if len(batches) != 1 {
		t.Fatalf(
			"finalized batches = %d, want 1",
			len(batches),
		)
	}

	verification, err :=
		VerifyManifest(batches[0].ManifestPath)

	if err != nil {
		t.Fatal(err)
	}

	if !verification.Verified {
		t.Fatal("published streaming batch did not independently verify")
	}

	if verification.Manifest.DataSHA256 !=
		batches[0].Manifest.DataSHA256 {
		t.Fatal("independent SHA-256 differs from streaming SHA-256")
	}

	if verification.Manifest.DataBytes !=
		batches[0].Manifest.DataBytes {
		t.Fatal("independent byte count differs from streaming byte count")
	}

	if verification.Manifest.RecordCount != 3 {
		t.Fatalf(
			"record count = %d, want 3",
			verification.Manifest.RecordCount,
		)
	}
}

func TestWriterRejectsRecordAboveHardByteLimit(t *testing.T) {
	writer := newBytePolicyTestWriter(t)

	writer.targetBatchBytes = 256
	writer.maxBatchBytes = 512
	writer.batchSize = 100

	err := writer.Append(
		"test",
		"scope",
		map[string]string{
			"value": strings.Repeat("x", 1024),
		},
	)

	if !errors.Is(err, ErrRecordTooLarge) {
		t.Fatalf(
			"Append() error = %v, want ErrRecordTooLarge",
			err,
		)
	}

	entries, readErr :=
		os.ReadDir(writer.dir)

	if readErr != nil {
		t.Fatal(readErr)
	}

	if len(entries) != 0 {
		t.Fatalf(
			"oversize record created %d spool artifacts, want 0",
			len(entries),
		)
	}
}

func newBytePolicyTestWriter(t *testing.T) *Writer {
	t.Helper()

	writer, err := NewWriter(
		t.TempDir(),
		DefaultBatchSize,
		CollectorIdentity{
			ExecutablePath:   `C:\Program Files\FI\fi.exe`,
			ExecutableSHA256: strings.Repeat("c", 64),
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	return writer
}
