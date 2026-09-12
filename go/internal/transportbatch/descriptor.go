// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportbatch

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode/utf8"
)

const (
	DescriptorVersion = "fi-transport-batch/0.1"
	signatureDomain   = "FI-BATCH-SIGNATURE-V1"
)

// Descriptor identifies one published FI source batch for Phase 2 transport.
//
// SourceID and BatchID form the transport identity. The record count, byte
// count, data hash, and manifest hash bind that identity to the exact published
// Phase 1 batch material.
type Descriptor struct {
	Version        string `json:"version"`
	SourceID       string `json:"source_id"`
	BatchID        string `json:"batch_id"`
	RecordCount    uint64 `json:"record_count"`
	DataBytes      uint64 `json:"data_bytes"`
	DataSHA256     string `json:"data_sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

// SignatureInput returns the deterministic byte sequence signed by the FI Batch
// Signing identity. The format is deliberately independent of JSON encoding.
//
// The input is:
//   - the fixed FI batch-signature domain and NUL separator;
//   - length-prefixed Version, SourceID, and BatchID UTF-8 values;
//   - RecordCount and DataBytes as unsigned 64-bit big-endian integers;
//   - the raw 32-byte data SHA-256 digest;
//   - the raw 32-byte manifest SHA-256 digest.
func (descriptor Descriptor) SignatureInput() ([]byte, error) {
	if err := descriptor.Validate(); err != nil {
		return nil, err
	}

	dataDigest, err := hex.DecodeString(descriptor.DataSHA256)
	if err != nil {
		return nil, fmt.Errorf("decode data SHA-256: %w", err)
	}

	manifestDigest, err := hex.DecodeString(descriptor.ManifestSHA256)
	if err != nil {
		return nil, fmt.Errorf("decode manifest SHA-256: %w", err)
	}

	value := make([]byte, 0, 128+len(descriptor.SourceID)+len(descriptor.BatchID))
	value = append(value, signatureDomain...)
	value = append(value, 0)
	value = appendLengthPrefixed(value, descriptor.Version)
	value = appendLengthPrefixed(value, descriptor.SourceID)
	value = appendLengthPrefixed(value, descriptor.BatchID)
	value = binary.BigEndian.AppendUint64(value, descriptor.RecordCount)
	value = binary.BigEndian.AppendUint64(value, descriptor.DataBytes)
	value = append(value, dataDigest...)
	value = append(value, manifestDigest...)

	return value, nil
}

// Validate verifies the Phase 2 transport descriptor contract before the
// descriptor is signed, transmitted, or accepted.
func (descriptor Descriptor) Validate() error {
	if descriptor.Version != DescriptorVersion {
		return fmt.Errorf(
			"descriptor version must be %q, got %q",
			DescriptorVersion,
			descriptor.Version,
		)
	}

	if err := validateText("source ID", descriptor.SourceID); err != nil {
		return err
	}

	if err := validateText("batch ID", descriptor.BatchID); err != nil {
		return err
	}

	if descriptor.RecordCount == 0 {
		return errors.New("record count must be greater than zero")
	}

	if descriptor.DataBytes == 0 {
		return errors.New("data byte count must be greater than zero")
	}

	if err := validateSHA256("data SHA-256", descriptor.DataSHA256); err != nil {
		return err
	}

	if err := validateSHA256(
		"manifest SHA-256",
		descriptor.ManifestSHA256,
	); err != nil {
		return err
	}

	return nil
}

func appendLengthPrefixed(value []byte, field string) []byte {
	value = binary.BigEndian.AppendUint32(value, uint32(len(field)))
	return append(value, field...)
}

func validateSHA256(name string, value string) error {
	if len(value) != 64 {
		return fmt.Errorf(
			"%s must contain exactly 64 lowercase hexadecimal characters",
			name,
		)
	}

	for _, character := range value {
		switch {
		case character >= '0' && character <= '9':
		case character >= 'a' && character <= 'f':
		default:
			return fmt.Errorf(
				"%s must contain exactly 64 lowercase hexadecimal characters",
				name,
			)
		}
	}

	return nil
}

func validateText(name string, value string) error {
	if value == "" {
		return fmt.Errorf("%s is required", name)
	}

	if !utf8.ValidString(value) {
		return fmt.Errorf("%s is not valid UTF-8", name)
	}

	return nil
}
