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
)

// DescriptorFromPublishedManifest constructs the Phase 2 transport descriptor
// from one finalized, verified, published Phase 1 spool batch.
//
// The published manifest remains authoritative for BatchID, RecordCount,
// DataBytes, and DataSHA256. ManifestSHA256 binds the descriptor to the exact
// published manifest bytes that remained stable across Phase 1 verification.
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
