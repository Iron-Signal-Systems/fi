// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteManifestDoesNotPublishUnverifiedPair(t *testing.T) {
	dir := t.TempDir()
	batchID := "publish-boundary"
	dataName := "batch-" + batchID + ".jsonl"
	dataPath := filepath.Join(dir, dataName)
	data := []byte("{}\n")
	if err := os.WriteFile(dataPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	manifestPath := filepath.Join(dir, "batch-"+batchID+".manifest.json")
	manifest := Manifest{
		Version:         ManifestVersion,
		BatchID:         batchID,
		TargetBatchSize: 1,
		RecordCount:     1,
		DataBytes:       int64(len(data)),
		DataSHA256:      strings.Repeat("0", 64), // valid format, intentionally wrong digest
		DataFile:        dataName,
		Collector: CollectorIdentity{
			ExecutablePath:   `C:\Program Files\FI\fi.exe`,
			ExecutableSHA256: strings.Repeat("a", 64),
		},
		CreatedAt:   "2026-09-07T00:00:00.000000000Z",
		CompletedAt: "2026-09-07T00:00:01.000000000Z",
	}

	if err := writeManifest(manifestPath, manifest); err == nil {
		t.Fatal("writeManifest published a manifest whose data pair did not verify")
	}
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Fatalf("final manifest was published despite failed verification: %v", err)
	}
	if _, err := os.Stat(manifestPath + ".open"); !os.IsNotExist(err) {
		t.Fatalf("private manifest was not cleaned after failed verification: %v", err)
	}
}
