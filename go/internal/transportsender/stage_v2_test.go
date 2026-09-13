// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportbatch"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportpackage"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportwire"
)

func TestPrepareOutboundFrameCreatesV2CompressedFrame(t *testing.T) {
	fixture := newOutboundStageFixture(t)

	result, err := PrepareOutboundFrame(fixture.config)
	if err != nil {
		t.Fatalf("PrepareOutboundFrame() error = %v", err)
	}
	if result.Sent.Descriptor.Version != transportbatch.DescriptorVersionV2 {
		t.Fatalf(
			"descriptor version = %q, want %q",
			result.Sent.Descriptor.Version,
			transportbatch.DescriptorVersionV2,
		)
	}
	if result.Sent.Descriptor.DataEncoding != transportencoding.DataEncodingZstd {
		t.Fatalf(
			"data encoding = %q, want %q",
			result.Sent.Descriptor.DataEncoding,
			transportencoding.DataEncodingZstd,
		)
	}
	if result.Sent.Descriptor.EncodedDataBytes == 0 {
		t.Fatal("encoded data byte count = 0, want non-zero")
	}
	if result.Sent.Descriptor.EncodedDataSHA256 == "" {
		t.Fatal("encoded data SHA-256 is empty")
	}

	stored, err := os.ReadFile(result.FramePath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	if len(stored) < len(outboundFrameMagicV2) {
		t.Fatalf("staged frame bytes = %d, want at least %d", len(stored), len(outboundFrameMagicV2))
	}
	if actual := string(stored[:len(outboundFrameMagicV2)]); actual != outboundFrameMagicV2 {
		t.Fatalf("staged frame magic = %q, want %q", actual, outboundFrameMagicV2)
	}
	assertNoOutboundOpenFiles(t, fixture.config.StageDir)
}

func TestPrepareOutboundFrameRejectsCorruptV2EncodedPayload(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	result, err := PrepareOutboundFrame(fixture.config)
	if err != nil {
		t.Fatalf("PrepareOutboundFrame() error = %v", err)
	}

	corrupt, err := os.ReadFile(result.FramePath)
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	corrupt[len(corrupt)-1] ^= 0xff
	if err := os.Chmod(result.FramePath, 0o600); err != nil {
		t.Fatalf("os.Chmod() writable error = %v", err)
	}
	if err := os.WriteFile(result.FramePath, corrupt, 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
	if err := os.Chmod(result.FramePath, 0o400); err != nil {
		t.Fatalf("os.Chmod() read-only error = %v", err)
	}

	_, err = validateStagedOutboundFrame(result.FramePath, result.Sent.Descriptor)
	if err == nil {
		t.Fatal("validateStagedOutboundFrame() error = nil, want corrupt encoded payload rejection")
	}
}

func TestPrepareOutboundFrameReusesLegacyV1Stage(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	legacy := writeLegacyV1OutboundStage(t, fixture)

	result, err := PrepareOutboundFrame(OutboundFrameConfig{
		ManifestPath: fixture.config.ManifestPath,
		SourceID:     fixture.config.SourceID,
		StageDir:     fixture.config.StageDir,
	})
	if err != nil {
		t.Fatalf("PrepareOutboundFrame() error = %v", err)
	}
	if result.Disposition != OutboundFrameDispositionExisting {
		t.Fatalf(
			"Disposition = %q, want %q",
			result.Disposition,
			OutboundFrameDispositionExisting,
		)
	}
	if result.Sent != legacy {
		t.Fatalf("reused sent frame = %#v, want %#v", result.Sent, legacy)
	}
	if result.Sent.Descriptor.Version != transportbatch.DescriptorVersion {
		t.Fatalf(
			"reused descriptor version = %q, want legacy %q",
			result.Sent.Descriptor.Version,
			transportbatch.DescriptorVersion,
		)
	}
	assertNoOutboundOpenFiles(t, fixture.config.StageDir)
}

func TestPrepareOutboundFrameReusesV2ExactStageWithoutSigner(t *testing.T) {
	fixture := newOutboundStageFixture(t)
	first, err := PrepareOutboundFrame(fixture.config)
	if err != nil {
		t.Fatalf("first PrepareOutboundFrame() error = %v", err)
	}
	before, err := os.ReadFile(first.FramePath)
	if err != nil {
		t.Fatalf("os.ReadFile() before retry error = %v", err)
	}

	retry, err := PrepareOutboundFrame(OutboundFrameConfig{
		ManifestPath: fixture.config.ManifestPath,
		SourceID:     fixture.config.SourceID,
		StageDir:     fixture.config.StageDir,
	})
	if err != nil {
		t.Fatalf("retry PrepareOutboundFrame() error = %v", err)
	}
	if retry.Sent.Descriptor.Version != transportbatch.DescriptorVersionV2 {
		t.Fatalf(
			"retry descriptor version = %q, want %q",
			retry.Sent.Descriptor.Version,
			transportbatch.DescriptorVersionV2,
		)
	}
	if retry.Sent != first.Sent {
		t.Fatalf("retry sent frame = %#v, want %#v", retry.Sent, first.Sent)
	}
	after, err := os.ReadFile(retry.FramePath)
	if err != nil {
		t.Fatalf("os.ReadFile() after retry error = %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("exact FIWB0002 stage changed during signer-free retry preparation")
	}
	assertNoOutboundOpenFiles(t, fixture.config.StageDir)
}

func writeLegacyV1OutboundStage(
	t *testing.T,
	fixture outboundStageFixture,
) SentFrame {
	t.Helper()

	descriptor, err := transportbatch.DescriptorFromPublishedManifest(
		fixture.config.SourceID,
		fixture.config.ManifestPath,
	)
	if err != nil {
		t.Fatalf("DescriptorFromPublishedManifest() error = %v", err)
	}
	manifest, err := os.ReadFile(fixture.config.ManifestPath)
	if err != nil {
		t.Fatalf("os.ReadFile() manifest error = %v", err)
	}
	signedBatch, err := transportpackage.NewSignedBatch(
		descriptor,
		fixture.config.BatchSigningCertificate,
		fixture.config.BatchSigner,
	)
	if err != nil {
		t.Fatalf("NewSignedBatch() error = %v", err)
	}

	path := filepath.Join(
		fixture.config.StageDir,
		outboundFrameObjectName(descriptor.SourceID, descriptor.BatchID),
	)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("os.OpenFile() legacy stage error = %v", err)
	}
	if err := transportwire.WriteHeader(file, signedBatch, manifest); err != nil {
		file.Close()
		t.Fatalf("WriteHeader() legacy stage error = %v", err)
	}
	if err := writeOutboundFull(file, manifest); err != nil {
		file.Close()
		t.Fatalf("write legacy manifest error = %v", err)
	}
	if err := writeOutboundFull(file, fixture.data); err != nil {
		file.Close()
		t.Fatalf("write legacy data error = %v", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		t.Fatalf("legacy stage Sync() error = %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("legacy stage Close() error = %v", err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatalf("legacy stage Chmod() error = %v", err)
	}

	sent, err := validateStagedOutboundFrame(path, descriptor)
	if err != nil {
		t.Fatalf("validateStagedOutboundFrame() legacy stage error = %v", err)
	}
	return sent
}
