// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportack"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportbatch"
)

// Test types.

type retirementFixture struct {
	authorization RetirementAuthorization
	batchID       string
	data          []byte
	dataPath      string
	manifest      []byte
	manifestPath  string
	sourceID      string
}

// Tests.

func TestRetirePublishedBatch(t *testing.T) {
	fixture := newRetirementFixture(t)

	result, err := RetirePublishedBatch(
		fixture.manifestPath,
		fixture.authorization,
	)
	if err != nil {
		t.Fatalf("RetirePublishedBatch() error = %v", err)
	}
	if result.Disposition != RetirementDispositionComplete {
		t.Fatalf(
			"Disposition = %q, want %q",
			result.Disposition,
			RetirementDispositionComplete,
		)
	}
	if !result.ManifestRemoved || !result.DataRemoved {
		t.Fatalf(
			"removed manifest=%t data=%t, want both true",
			result.ManifestRemoved,
			result.DataRemoved,
		)
	}
	if result.SourceID != fixture.sourceID || result.BatchID != fixture.batchID {
		t.Fatalf("result identity = (%q, %q), want (%q, %q)", result.SourceID, result.BatchID, fixture.sourceID, fixture.batchID)
	}
	assertPathMissing(t, fixture.manifestPath)
	assertPathMissing(t, fixture.dataPath)
}

func TestRetirePublishedBatchAlreadyComplete(t *testing.T) {
	fixture := newRetirementFixture(t)
	if err := os.Remove(fixture.manifestPath); err != nil {
		t.Fatalf("remove manifest fixture: %v", err)
	}
	if err := os.Remove(fixture.dataPath); err != nil {
		t.Fatalf("remove data fixture: %v", err)
	}

	result, err := RetirePublishedBatch(fixture.manifestPath, fixture.authorization)
	if err != nil {
		t.Fatalf("RetirePublishedBatch() error = %v", err)
	}
	if result.Disposition != RetirementDispositionAlreadyComplete {
		t.Fatalf(
			"Disposition = %q, want %q",
			result.Disposition,
			RetirementDispositionAlreadyComplete,
		)
	}
	if result.ManifestRemoved || result.DataRemoved {
		t.Fatal("already-complete retirement reported new removals")
	}
}

func TestRetirePublishedBatchRejectsDataMismatchWithoutRemovingAnything(t *testing.T) {
	fixture := newRetirementFixture(t)
	bad := append([]byte(nil), fixture.data...)
	bad[0] ^= 0x01
	if err := os.WriteFile(fixture.dataPath, bad, 0o600); err != nil {
		t.Fatalf("replace data fixture: %v", err)
	}

	_, err := RetirePublishedBatch(fixture.manifestPath, fixture.authorization)
	if err == nil {
		t.Fatal("RetirePublishedBatch() error = nil, want data mismatch")
	}
	if !strings.Contains(err.Error(), "data SHA-256") {
		t.Fatalf("RetirePublishedBatch() error = %q, want data SHA-256 mismatch", err)
	}
	assertPathContains(t, fixture.manifestPath, fixture.manifest)
	assertPathContains(t, fixture.dataPath, bad)
}

func TestRetirePublishedBatchRejectsManifestMismatchWithoutRemovingAnything(t *testing.T) {
	fixture := newRetirementFixture(t)
	bad := append([]byte(nil), fixture.manifest...)
	bad[0] ^= 0x01
	if err := os.WriteFile(fixture.manifestPath, bad, 0o600); err != nil {
		t.Fatalf("replace manifest fixture: %v", err)
	}

	_, err := RetirePublishedBatch(fixture.manifestPath, fixture.authorization)
	if err == nil {
		t.Fatal("RetirePublishedBatch() error = nil, want manifest mismatch")
	}
	if !strings.Contains(err.Error(), "manifest SHA-256") {
		t.Fatalf("RetirePublishedBatch() error = %q, want manifest SHA-256 mismatch", err)
	}
	assertPathContains(t, fixture.manifestPath, bad)
	assertPathContains(t, fixture.dataPath, fixture.data)
}

func TestRetirePublishedBatchRejectsNonRegularDataWithoutRemovingManifest(t *testing.T) {
	fixture := newRetirementFixture(t)
	if err := os.Remove(fixture.dataPath); err != nil {
		t.Fatalf("remove data fixture: %v", err)
	}
	if err := os.Mkdir(fixture.dataPath, 0o700); err != nil {
		t.Fatalf("create data directory fixture: %v", err)
	}

	_, err := RetirePublishedBatch(fixture.manifestPath, fixture.authorization)
	if err == nil {
		t.Fatal("RetirePublishedBatch() error = nil, want non-regular data rejection")
	}
	if !strings.Contains(err.Error(), "data must be a regular file") {
		t.Fatalf("RetirePublishedBatch() error = %q, want regular-file rejection", err)
	}
	assertPathContains(t, fixture.manifestPath, fixture.manifest)
}

func TestRetirePublishedBatchRejectsWrongManifestFilename(t *testing.T) {
	fixture := newRetirementFixture(t)
	wrongPath := filepath.Join(filepath.Dir(fixture.manifestPath), "other.manifest.json")
	if err := os.WriteFile(wrongPath, fixture.manifest, 0o600); err != nil {
		t.Fatalf("write wrong manifest fixture: %v", err)
	}

	_, err := RetirePublishedBatch(wrongPath, fixture.authorization)
	if err == nil {
		t.Fatal("RetirePublishedBatch() error = nil, want filename rejection")
	}
	if !strings.Contains(err.Error(), "manifest filename") {
		t.Fatalf("RetirePublishedBatch() error = %q, want filename rejection", err)
	}
	assertPathContains(t, fixture.manifestPath, fixture.manifest)
	assertPathContains(t, fixture.dataPath, fixture.data)
}

func TestRetirePublishedBatchRejectsZeroAuthorization(t *testing.T) {
	fixture := newRetirementFixture(t)

	_, err := RetirePublishedBatch(fixture.manifestPath, RetirementAuthorization{})
	if err == nil {
		t.Fatal("RetirePublishedBatch() error = nil, want authorization rejection")
	}
	if !strings.Contains(err.Error(), "retirement authorization") {
		t.Fatalf("RetirePublishedBatch() error = %q, want authorization rejection", err)
	}
	assertPathContains(t, fixture.manifestPath, fixture.manifest)
	assertPathContains(t, fixture.dataPath, fixture.data)
}

func TestRetirePublishedBatchResumesAfterDataWasAlreadyRemoved(t *testing.T) {
	fixture := newRetirementFixture(t)
	if err := os.Remove(fixture.dataPath); err != nil {
		t.Fatalf("remove data fixture: %v", err)
	}

	result, err := RetirePublishedBatch(fixture.manifestPath, fixture.authorization)
	if err != nil {
		t.Fatalf("RetirePublishedBatch() error = %v", err)
	}
	if result.Disposition != RetirementDispositionResumed {
		t.Fatalf("Disposition = %q, want %q", result.Disposition, RetirementDispositionResumed)
	}
	if !result.ManifestRemoved || result.DataRemoved {
		t.Fatalf("removed manifest=%t data=%t, want true/false", result.ManifestRemoved, result.DataRemoved)
	}
	assertPathMissing(t, fixture.manifestPath)
	assertPathMissing(t, fixture.dataPath)
}

func TestRetirePublishedBatchResumesAfterManifestWasAlreadyRemoved(t *testing.T) {
	fixture := newRetirementFixture(t)
	if err := os.Remove(fixture.manifestPath); err != nil {
		t.Fatalf("remove manifest fixture: %v", err)
	}

	result, err := RetirePublishedBatch(fixture.manifestPath, fixture.authorization)
	if err != nil {
		t.Fatalf("RetirePublishedBatch() error = %v", err)
	}
	if result.Disposition != RetirementDispositionResumed {
		t.Fatalf("Disposition = %q, want %q", result.Disposition, RetirementDispositionResumed)
	}
	if result.ManifestRemoved || !result.DataRemoved {
		t.Fatalf("removed manifest=%t data=%t, want false/true", result.ManifestRemoved, result.DataRemoved)
	}
	assertPathMissing(t, fixture.manifestPath)
	assertPathMissing(t, fixture.dataPath)
}

// Test helpers.

func assertPathContains(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) error = %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("path %q contains %q, want %q", path, got, want)
	}
}

func assertPathMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("os.Lstat(%q) error = %v, want not exist", path, err)
	}
}

func newRetirementFixture(t *testing.T) retirementFixture {
	t.Helper()

	const sourceID = "iss-fs-01.iss.local"
	const batchID = "20260912T220000.000000000Z-0011223344556677"

	root := t.TempDir()
	data := []byte("{\"record\":1}\n{\"record\":2}\n")
	dataPath := filepath.Join(root, "batch-"+batchID+".jsonl")
	if err := os.WriteFile(dataPath, data, 0o600); err != nil {
		t.Fatalf("write data fixture: %v", err)
	}

	dataDigest := sha256.Sum256(data)
	dataSHA256 := hex.EncodeToString(dataDigest[:])
	manifest := []byte(`{
  "version": "fi-batch-manifest/0.1",
  "batch_id": "` + batchID + `",
  "target_batch_size": 64,
  "record_count": 2,
  "data_bytes": ` + "26" + `,
  "data_sha256": "` + dataSHA256 + `",
  "data_file": "batch-` + batchID + `.jsonl",
  "collector": {
    "executable_path": "C:\\Program Files\\FI\\fi.exe",
    "executable_sha256": "` + strings.Repeat("a", 64) + `"
  },
  "created_at": "2026-09-12T22:00:00.000000000Z",
  "completed_at": "2026-09-12T22:00:01.000000000Z"
}
`)
	// Keep the fixture self-consistent even if the data literal changes later.
	manifest = bytes.ReplaceAll(manifest, []byte(`"data_bytes": 26`), []byte(`"data_bytes": `+fmtUint(len(data))))
	manifestPath := filepath.Join(root, "batch-"+batchID+".manifest.json")
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatalf("write manifest fixture: %v", err)
	}
	manifestDigest := sha256.Sum256(manifest)
	manifestSHA256 := hex.EncodeToString(manifestDigest[:])

	descriptor := transportbatch.Descriptor{
		Version:        transportbatch.DescriptorVersion,
		SourceID:       sourceID,
		BatchID:        batchID,
		RecordCount:    2,
		DataBytes:      uint64(len(data)),
		DataSHA256:     dataSHA256,
		ManifestSHA256: manifestSHA256,
	}
	frame := []byte("exact-fi-wire-frame-for-retirement-test")
	frameDigest := sha256.Sum256(frame)
	sent := SentFrame{
		Descriptor:  descriptor,
		FrameBytes:  uint64(len(frame)),
		FrameSHA256: hex.EncodeToString(frameDigest[:]),
	}
	acknowledgement, err := transportack.NewDurableAcknowledgement(
		transportack.OutcomeDurableNew,
		sourceID,
		batchID,
		uint64(len(data)),
		dataSHA256,
		manifestSHA256,
		uint64(len(frame)),
		hex.EncodeToString(frameDigest[:]),
	)
	if err != nil {
		t.Fatalf("transportack.NewDurableAcknowledgement() error = %v", err)
	}
	var encoded bytes.Buffer
	if err := transportack.WriteAcknowledgement(&encoded, acknowledgement); err != nil {
		t.Fatalf("transportack.WriteAcknowledgement() error = %v", err)
	}
	authorization, err := VerifyDurableAcknowledgement(bytes.NewReader(encoded.Bytes()), sent)
	if err != nil {
		t.Fatalf("VerifyDurableAcknowledgement() error = %v", err)
	}

	return retirementFixture{
		authorization: authorization,
		batchID:       batchID,
		data:          data,
		dataPath:      dataPath,
		manifest:      manifest,
		manifestPath:  manifestPath,
		sourceID:      sourceID,
	}
}

func fmtUint(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}
