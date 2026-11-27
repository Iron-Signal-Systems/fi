// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportbatch

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func TestDescriptorFromPublishedManifest(t *testing.T) {
	dir := t.TempDir()
	manifestPath, manifest := writePublishedBatch(t, dir)

	descriptor, err := DescriptorFromPublishedManifest(
		"iss-fs-01.iss.local",
		manifestPath,
	)
	if err != nil {
		t.Fatalf("DescriptorFromPublishedManifest() error = %v", err)
	}

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	manifestDigest := sha256.Sum256(manifestBytes)

	if descriptor.Version != DescriptorVersion {
		t.Fatalf("Version = %q, want %q", descriptor.Version, DescriptorVersion)
	}
	if descriptor.SourceID != "iss-fs-01.iss.local" {
		t.Fatalf("SourceID = %q, want enrolled source ID", descriptor.SourceID)
	}
	if descriptor.BatchID != manifest.BatchID {
		t.Fatalf("BatchID = %q, want %q", descriptor.BatchID, manifest.BatchID)
	}
	if descriptor.RecordCount != uint64(manifest.RecordCount) {
		t.Fatalf(
			"RecordCount = %d, want %d",
			descriptor.RecordCount,
			manifest.RecordCount,
		)
	}
	if descriptor.DataBytes != uint64(manifest.DataBytes) {
		t.Fatalf(
			"DataBytes = %d, want %d",
			descriptor.DataBytes,
			manifest.DataBytes,
		)
	}
	if descriptor.DataSHA256 != manifest.DataSHA256 {
		t.Fatalf(
			"DataSHA256 = %q, want %q",
			descriptor.DataSHA256,
			manifest.DataSHA256,
		)
	}
	if descriptor.ManifestSHA256 != hex.EncodeToString(manifestDigest[:]) {
		t.Fatalf(
			"ManifestSHA256 = %q, want exact published manifest digest",
			descriptor.ManifestSHA256,
		)
	}
}

func TestDescriptorFromPublishedManifestBindsExactManifestBytes(t *testing.T) {
	dir := t.TempDir()
	manifestPath, _ := writePublishedBatch(t, dir)

	file, err := os.OpenFile(manifestPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("os.OpenFile() error = %v", err)
	}
	if _, err := file.WriteString(" \n"); err != nil {
		file.Close()
		t.Fatalf("append manifest whitespace: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close manifest: %v", err)
	}

	descriptor, err := DescriptorFromPublishedManifest(
		"iss-fs-01.iss.local",
		manifestPath,
	)
	if err != nil {
		t.Fatalf("DescriptorFromPublishedManifest() error = %v", err)
	}

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	manifestDigest := sha256.Sum256(manifestBytes)
	want := hex.EncodeToString(manifestDigest[:])
	if descriptor.ManifestSHA256 != want {
		t.Fatalf(
			"ManifestSHA256 = %q, want %q",
			descriptor.ManifestSHA256,
			want,
		)
	}
}

func TestDescriptorFromPublishedManifestRejectsInvalidSourceID(t *testing.T) {
	if _, err := DescriptorFromPublishedManifest("", "unused"); err == nil {
		t.Fatal("DescriptorFromPublishedManifest() error = nil, want source ID rejection")
	}
}

func TestDescriptorFromPublishedManifestRejectsTamperedData(t *testing.T) {
	dir := t.TempDir()
	manifestPath, manifest := writePublishedBatch(t, dir)
	dataPath := filepath.Join(dir, manifest.DataFile)

	file, err := os.OpenFile(dataPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("os.OpenFile() error = %v", err)
	}
	if _, err := file.WriteString("tampered\n"); err != nil {
		file.Close()
		t.Fatalf("tamper data file: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close data file: %v", err)
	}

	if _, err := DescriptorFromPublishedManifest(
		"iss-fs-01.iss.local",
		manifestPath,
	); err == nil {
		t.Fatal("DescriptorFromPublishedManifest() error = nil, want tampered-data rejection")
	}
}

func TestDescriptorFromPublishedManifestRejectsUnpublishedFilename(t *testing.T) {
	dir := t.TempDir()
	manifestPath, manifest := writePublishedBatch(t, dir)

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	unpublishedPath := filepath.Join(
		dir,
		"batch-"+manifest.BatchID+".manifest.json.open",
	)
	if err := os.WriteFile(unpublishedPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}

	_, err = DescriptorFromPublishedManifest(
		"iss-fs-01.iss.local",
		unpublishedPath,
	)
	if err == nil {
		t.Fatal("DescriptorFromPublishedManifest() error = nil, want unpublished filename rejection")
	}
	if !strings.Contains(err.Error(), "published FI batch manifest filename") {
		t.Fatalf(
			"DescriptorFromPublishedManifest() error = %q, want published filename rejection",
			err,
		)
	}
}

func writePublishedBatch(t *testing.T, dir string) (string, spool.Manifest) {
	t.Helper()

	const batchID = "20260912T180000.000000000Z-0011223344556677"
	data := []byte("{\"record\":1}\n")
	dataDigest := sha256.Sum256(data)
	dataName := "batch-" + batchID + ".jsonl"
	dataPath := filepath.Join(dir, dataName)
	if err := os.WriteFile(dataPath, data, 0o600); err != nil {
		t.Fatalf("write batch data: %v", err)
	}

	manifest := spool.Manifest{
		Version:         spool.ManifestVersion,
		BatchID:         batchID,
		TargetBatchSize: 64,
		RecordCount:     1,
		DataBytes:       int64(len(data)),
		DataSHA256:      hex.EncodeToString(dataDigest[:]),
		DataFile:        dataName,
		Collector: spool.CollectorIdentity{
			ExecutablePath:   `C:\Program Files\FI\fi.exe`,
			ExecutableSHA256: strings.Repeat("a", 64),
		},
		CreatedAt:   "2026-09-12T18:00:00.000000000Z",
		CompletedAt: "2026-09-12T18:00:01.000000000Z",
	}

	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("json.MarshalIndent() error = %v", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	manifestPath := filepath.Join(
		dir,
		"batch-"+batchID+".manifest.json",
	)
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatalf("write batch manifest: %v", err)
	}

	return manifestPath, manifest
}
