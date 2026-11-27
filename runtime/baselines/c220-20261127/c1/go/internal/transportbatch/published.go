// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportbatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
)

// EncodedRepresentation describes the exact bytes produced from the canonical
// Phase 1 JSONL batch for transport. These facts become part of descriptor 0.2
// and therefore part of the source batch signature.
type EncodedRepresentation struct {
	DataEncoding      string
	EncodedDataBytes  uint64
	EncodedDataSHA256 string
}

// DescriptorFromPublishedManifest constructs the original Phase 2 descriptor
// from one finalized, verified, published Phase 1 spool batch.
//
// The published manifest remains authoritative for BatchID, RecordCount,
// DataBytes, and DataSHA256. ManifestSHA256 binds the descriptor to the exact
// published manifest bytes that remained stable across Phase 1 verification.
//
// New outbound transport work should use DescriptorFromPublishedManifestV2.
// This function remains for exact validation and replay of already-staged 0.1
// frames while the 0.2 transport representation is introduced.
func DescriptorFromPublishedManifest(
	sourceID string,
	manifestPath string,
) (Descriptor, error) {
	if err := validateText("source ID", sourceID); err != nil {
		return Descriptor{}, err
	}

	if manifestPath == "" {
		return Descriptor{}, errors.New("published manifest path is required")
	}

	before, err := os.ReadFile(manifestPath)
	if err != nil {
		return Descriptor{}, fmt.Errorf("read published FI batch manifest: %w", err)
	}

	verification, err := spool.VerifyManifest(manifestPath)
	if err != nil {
		return Descriptor{}, fmt.Errorf("verify published FI batch manifest: %w", err)
	}
	if !verification.Verified {
		return Descriptor{}, errors.New("published FI batch manifest did not verify")
	}

	after, err := os.ReadFile(manifestPath)
	if err != nil {
		return Descriptor{}, fmt.Errorf(
			"re-read published FI batch manifest after verification: %w",
			err,
		)
	}
	if !bytes.Equal(before, after) {
		return Descriptor{}, errors.New(
			"published FI batch manifest changed during transport descriptor construction",
		)
	}

	manifest := verification.Manifest
	expectedManifestName := "batch-" + manifest.BatchID + ".manifest.json"
	if filepath.Base(manifestPath) != expectedManifestName {
		return Descriptor{}, fmt.Errorf(
			"published FI batch manifest filename must be %q",
			expectedManifestName,
		)
	}

	if manifest.RecordCount <= 0 {
		return Descriptor{}, errors.New(
			"verified FI batch manifest record count must be greater than zero",
		)
	}
	if manifest.DataBytes <= 0 {
		return Descriptor{}, errors.New(
			"verified FI batch manifest data byte count must be greater than zero",
		)
	}

	manifestDigest := sha256.Sum256(after)
	descriptor := Descriptor{
		Version:        DescriptorVersion,
		SourceID:       sourceID,
		BatchID:        manifest.BatchID,
		RecordCount:    uint64(manifest.RecordCount),
		DataBytes:      uint64(manifest.DataBytes),
		DataSHA256:     manifest.DataSHA256,
		ManifestSHA256: hex.EncodeToString(manifestDigest[:]),
	}

	if err := descriptor.Validate(); err != nil {
		return Descriptor{}, fmt.Errorf(
			"validate descriptor from published FI batch: %w",
			err,
		)
	}

	return descriptor, nil
}

// DescriptorFromPublishedManifestV2 binds one verified published Phase 1 batch
// to one exact zstd transport representation.
//
// The canonical JSONL facts remain those published by Phase 1. FI does not
// replace them with compressed facts. The encoded byte count and hash are
// additional signed facts describing the exact bytes placed on the 0.2 wire.
func DescriptorFromPublishedManifestV2(
	sourceID string,
	manifestPath string,
	representation EncodedRepresentation,
) (Descriptor, error) {
	if err := representation.Validate(); err != nil {
		return Descriptor{}, err
	}

	descriptor, err := DescriptorFromPublishedManifest(sourceID, manifestPath)
	if err != nil {
		return Descriptor{}, err
	}

	descriptor.Version = DescriptorVersionV2
	descriptor.DataEncoding = representation.DataEncoding
	descriptor.EncodedDataBytes = representation.EncodedDataBytes
	descriptor.EncodedDataSHA256 = representation.EncodedDataSHA256

	if err := descriptor.Validate(); err != nil {
		return Descriptor{}, fmt.Errorf(
			"validate descriptor 0.2 from published FI batch: %w",
			err,
		)
	}

	return descriptor, nil
}

// Validate verifies that an encoded representation is complete and uses FI's
// fixed Phase 2.2 zstd transport encoding.
func (representation EncodedRepresentation) Validate() error {
	if representation.DataEncoding != transportencoding.DataEncodingZstd {
		return fmt.Errorf(
			"encoded representation data encoding must be %q, got %q",
			transportencoding.DataEncodingZstd,
			representation.DataEncoding,
		)
	}
	if representation.EncodedDataBytes == 0 {
		return errors.New(
			"encoded representation byte count must be greater than zero",
		)
	}
	if err := validateSHA256(
		"encoded representation SHA-256",
		representation.EncodedDataSHA256,
	); err != nil {
		return err
	}

	return nil
}
