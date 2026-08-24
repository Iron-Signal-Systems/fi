// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"os"
	"testing"
)

func TestWriterBatchesAndVerifies(t *testing.T) {
	writer, err := NewWriter(t.TempDir(), 4, CollectorIdentity{
		ExecutablePath:   `C:\Program Files\FI\fi.exe`,
		ExecutableSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := writer.Append("FileObservation", "scope-test", map[string]any{"index": i}); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	batches := writer.FinalizedBatches()
	if len(batches) != 2 {
		t.Fatalf("batches = %d, want 2", len(batches))
	}
	if batches[0].Manifest.RecordCount != 4 || batches[1].Manifest.RecordCount != 1 {
		t.Fatalf("record counts = %d, %d", batches[0].Manifest.RecordCount, batches[1].Manifest.RecordCount)
	}
	for _, batch := range batches {
		verification, err := VerifyManifest(batch.ManifestPath)
		if err != nil {
			t.Fatal(err)
		}
		if !verification.Verified {
			t.Fatal("batch was not verified")
		}
	}
}

func TestVerifyManifestDetectsTamper(t *testing.T) {
	writer, err := NewWriter(t.TempDir(), 2, CollectorIdentity{
		ExecutablePath:   `C:\Program Files\FI\fi.exe`,
		ExecutableSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Append("FileObservation", "scope-test", map[string]string{"name": "one"}); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	batch := writer.FinalizedBatches()[0]
	file, err := os.OpenFile(batch.DataPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("tamper\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(batch.ManifestPath); err == nil {
		t.Fatal("tampered batch verified")
	}
}
