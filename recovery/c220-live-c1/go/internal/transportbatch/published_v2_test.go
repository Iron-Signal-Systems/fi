// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportbatch

import (
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
)

func TestDescriptorFromPublishedManifestV2(t *testing.T) {
	dir := t.TempDir()
	manifestPath, manifest := writePublishedBatch(t, dir)

	representation := EncodedRepresentation{
		DataEncoding:     transportencoding.DataEncodingZstd,
		EncodedDataBytes: 321,
		EncodedDataSHA256: strings.Repeat(
			"12",
			32,
		),
	}

	descriptor, err := DescriptorFromPublishedManifestV2(
		"iss-fs-01.iss.local",
		manifestPath,
		representation,
	)
	if err != nil {
		t.Fatalf("DescriptorFromPublishedManifestV2() error = %v", err)
	}

	if descriptor.Version != DescriptorVersionV2 {
		t.Fatalf(
			"Version = %q, want %q",
			descriptor.Version,
			DescriptorVersionV2,
		)
	}
	if descriptor.BatchID != manifest.BatchID {
		t.Fatalf(
			"BatchID = %q, want %q",
			descriptor.BatchID,
			manifest.BatchID,
		)
	}
	if descriptor.DataBytes != uint64(manifest.DataBytes) {
		t.Fatalf(
			"DataBytes = %d, want canonical %d",
			descriptor.DataBytes,
			manifest.DataBytes,
		)
	}
	if descriptor.DataSHA256 != manifest.DataSHA256 {
		t.Fatalf(
			"DataSHA256 = %q, want canonical %q",
			descriptor.DataSHA256,
			manifest.DataSHA256,
		)
	}
	if descriptor.DataEncoding != representation.DataEncoding {
		t.Fatalf(
			"DataEncoding = %q, want %q",
			descriptor.DataEncoding,
			representation.DataEncoding,
		)
	}
	if descriptor.EncodedDataBytes != representation.EncodedDataBytes {
		t.Fatalf(
			"EncodedDataBytes = %d, want %d",
			descriptor.EncodedDataBytes,
			representation.EncodedDataBytes,
		)
	}
	if descriptor.EncodedDataSHA256 != representation.EncodedDataSHA256 {
		t.Fatalf(
			"EncodedDataSHA256 = %q, want %q",
			descriptor.EncodedDataSHA256,
			representation.EncodedDataSHA256,
		)
	}
}

func TestDescriptorFromPublishedManifestV2RejectsInvalidRepresentation(
	t *testing.T,
) {
	dir := t.TempDir()
	manifestPath, _ := writePublishedBatch(t, dir)

	_, err := DescriptorFromPublishedManifestV2(
		"iss-fs-01.iss.local",
		manifestPath,
		EncodedRepresentation{
			DataEncoding:      "gzip",
			EncodedDataBytes:  123,
			EncodedDataSHA256: strings.Repeat("12", 32),
		},
	)
	if err == nil {
		t.Fatal(
			"DescriptorFromPublishedManifestV2() error = nil, want invalid encoding rejection",
		)
	}
}

func TestEncodedRepresentationValidate(t *testing.T) {
	value := EncodedRepresentation{
		DataEncoding:      transportencoding.DataEncodingZstd,
		EncodedDataBytes:  123,
		EncodedDataSHA256: strings.Repeat("ab", 32),
	}

	if err := value.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}
