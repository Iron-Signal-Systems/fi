// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"os"
	"path/filepath"
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
func TestDurableRenameMovesFile(t *testing.T) {
	dir := t.TempDir()
	source := dir + string(os.PathSeparator) + "source.open"
	destination := dir + string(os.PathSeparator) + "destination.jsonl"

	if err := os.WriteFile(source, []byte("durable-rename-test"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := durableRename(source, destination); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatalf("source still exists after rename: %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "durable-rename-test" {
		t.Fatalf("destination content = %q", string(got))
	}
}
func TestPreserveInterruptedArtifactsMovesOpenData(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "batch-test-open.open")
	content := []byte("partial-spool-bytes\n")
	if err := os.WriteFile(source, content, 0o600); err != nil {
		t.Fatal(err)
	}

	summary, err := PreserveInterruptedArtifacts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if summary.PreservedCount != 1 || len(summary.Preserved) != 1 {
		t.Fatalf(
			"preserved = %d/%d, want 1/1",
			summary.PreservedCount,
			len(summary.Preserved),
		)
	}
	if summary.Preserved[0].Kind != InterruptedOpenData {
		t.Fatalf("kind = %q", summary.Preserved[0].Kind)
	}
	if _, err := os.Stat(source); !os.IsNotExist(err) {
		t.Fatalf("source still exists: %v", err)
	}
	got, err := os.ReadFile(summary.Preserved[0].PreservedPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatalf("preserved content = %q", string(got))
	}
}

func TestPreserveInterruptedArtifactsMovesOrphanFinalizedData(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "batch-test-orphan.jsonl")
	if err := os.WriteFile(source, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	summary, err := PreserveInterruptedArtifacts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if summary.PreservedCount != 1 {
		t.Fatalf("preserved_count = %d, want 1", summary.PreservedCount)
	}
	if summary.Preserved[0].Kind != InterruptedOrphanData {
		t.Fatalf("kind = %q", summary.Preserved[0].Kind)
	}
}

func TestPreserveInterruptedArtifactsMovesOrphanFinalizedManifest(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "batch-test-orphan.manifest.json")
	if err := os.WriteFile(source, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	summary, err := PreserveInterruptedArtifacts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if summary.PreservedCount != 1 {
		t.Fatalf("preserved_count = %d, want 1", summary.PreservedCount)
	}
	if summary.Preserved[0].Kind != InterruptedOrphanManifest {
		t.Fatalf("kind = %q", summary.Preserved[0].Kind)
	}
}

func TestPreserveInterruptedArtifactsLeavesFinalizedPair(t *testing.T) {
	dir := t.TempDir()
	dataPath := filepath.Join(dir, "batch-test-final.jsonl")
	manifestPath := filepath.Join(dir, "batch-test-final.manifest.json")
	if err := os.WriteFile(dataPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	summary, err := PreserveInterruptedArtifacts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if summary.PreservedCount != 0 {
		t.Fatalf("preserved_count = %d, want 0", summary.PreservedCount)
	}
	if _, err := os.Stat(dataPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatal(err)
	}
}

func TestPreserveInterruptedArtifactsMovesOpenManifestBesideFinalizedPair(t *testing.T) {
	dir := t.TempDir()
	dataPath := filepath.Join(dir, "batch-test-final.jsonl")
	manifestPath := filepath.Join(dir, "batch-test-final.manifest.json")
	openManifestPath := manifestPath + ".open"
	if err := os.WriteFile(dataPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(openManifestPath, []byte("partial\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	summary, err := PreserveInterruptedArtifacts(dir)
	if err != nil {
		t.Fatal(err)
	}
	if summary.PreservedCount != 1 {
		t.Fatalf("preserved_count = %d, want 1", summary.PreservedCount)
	}
	if summary.Preserved[0].Kind != InterruptedOpenManifest {
		t.Fatalf("kind = %q", summary.Preserved[0].Kind)
	}
	if _, err := os.Stat(dataPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(openManifestPath); !os.IsNotExist(err) {
		t.Fatalf("open manifest still exists: %v", err)
	}
}
