// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportbatch"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportpackage"
)

const (
	fixedHeaderBytes = 120
	frameMagic       = "FIWB0001"

	MaxManifestBytes = 1024 * 1024
	MaxTextBytes     = 4 * 1024
	MaxVersionBytes  = 64
)

// Header is the bounded Phase 2 wire prelude for one signed FI batch.
//
// It carries the signed batch package plus the exact byte length of the
// published manifest that follows the header. The batch data immediately follows
// that manifest and its byte length comes from the signed descriptor.
//
// The framing contract deliberately does not carry an algorithm identifier.
// SignedBatch version 0.1 has one fixed signature algorithm contract.
type Header struct {
	SignedBatch   transportpackage.SignedBatch
	ManifestBytes uint64
}

func headerFromManifest(
	signedBatch transportpackage.SignedBatch,
	manifest []byte,
) (Header, error) {
	if err := signedBatch.Validate(); err != nil {
		return Header{}, fmt.Errorf("validate signed batch: %w", err)
	}
	if len(manifest) == 0 {
		return Header{}, errors.New("published manifest bytes are required")
	}
	if len(manifest) > MaxManifestBytes {
		return Header{}, fmt.Errorf(
			"published manifest exceeds %d bytes",
			MaxManifestBytes,
		)
	}

	digest := sha256.Sum256(manifest)
	if hex.EncodeToString(digest[:]) != signedBatch.Descriptor.ManifestSHA256 {
		return Header{}, errors.New(
			"published manifest SHA-256 does not match signed descriptor",
		)
	}

	value := Header{
		SignedBatch:   cloneSignedBatch(signedBatch),
		ManifestBytes: uint64(len(manifest)),
	}
	if err := value.Validate(); err != nil {
		return Header{}, err
	}

	return value, nil
}

// ReadHeader reads exactly one bounded FI wire header. It stops before the
// published manifest payload, leaving the reader positioned at its first byte.
func ReadHeader(reader io.Reader) (Header, error) {
	if reader == nil {
		return Header{}, errors.New("wire reader is required")
	}

	fixed := make([]byte, fixedHeaderBytes)
	if _, err := io.ReadFull(reader, fixed); err != nil {
		return Header{}, fmt.Errorf("read FI wire fixed header: %w", err)
	}
	if string(fixed[:len(frameMagic)]) != frameMagic {
		return Header{}, errors.New("FI wire frame magic is invalid")
	}

	signedVersionBytes := binary.BigEndian.Uint32(fixed[8:12])
	descriptorVersionBytes := binary.BigEndian.Uint32(fixed[12:16])
	sourceIDBytes := binary.BigEndian.Uint32(fixed[16:20])
	batchIDBytes := binary.BigEndian.Uint32(fixed[20:24])
	recordCount := binary.BigEndian.Uint64(fixed[24:32])
	dataBytes := binary.BigEndian.Uint64(fixed[32:40])
	manifestBytes := binary.BigEndian.Uint64(fixed[40:48])
	dataSHA256 := hex.EncodeToString(fixed[48:80])
	manifestSHA256 := hex.EncodeToString(fixed[80:112])
	signatureBytes := binary.BigEndian.Uint32(fixed[112:116])
	certificateBytes := binary.BigEndian.Uint32(fixed[116:120])

	if err := validateLengths(
		signedVersionBytes,
		descriptorVersionBytes,
		sourceIDBytes,
		batchIDBytes,
		signatureBytes,
		certificateBytes,
		manifestBytes,
	); err != nil {
		return Header{}, err
	}

	signedVersion, err := readString(reader, signedVersionBytes, "signed batch version")
	if err != nil {
		return Header{}, err
	}
	descriptorVersion, err := readString(reader, descriptorVersionBytes, "descriptor version")
	if err != nil {
		return Header{}, err
	}
	sourceID, err := readString(reader, sourceIDBytes, "source ID")
	if err != nil {
		return Header{}, err
	}
	batchID, err := readString(reader, batchIDBytes, "batch ID")
	if err != nil {
		return Header{}, err
	}
	signature, err := readBytes(reader, signatureBytes, "batch signature")
	if err != nil {
		return Header{}, err
	}
	certificateDER, err := readBytes(
		reader,
		certificateBytes,
		"batch-signing certificate DER",
	)
	if err != nil {
		return Header{}, err
	}

	value := Header{
		SignedBatch: transportpackage.SignedBatch{
			Version: signedVersion,
			Descriptor: transportbatch.Descriptor{
				Version:        descriptorVersion,
				SourceID:       sourceID,
				BatchID:        batchID,
				RecordCount:    recordCount,
				DataBytes:      dataBytes,
				DataSHA256:     dataSHA256,
				ManifestSHA256: manifestSHA256,
			},
			Signature:                  signature,
			BatchSigningCertificateDER: certificateDER,
		},
		ManifestBytes: manifestBytes,
	}
	if err := value.Validate(); err != nil {
		return Header{}, fmt.Errorf("validate FI wire header: %w", err)
	}

	return value, nil
}

// Validate verifies the bounded wire framing contract without consuming the
// manifest or data payload that follows the header.
func (value Header) Validate() error {
	if err := value.SignedBatch.Validate(); err != nil {
		return fmt.Errorf("validate signed batch: %w", err)
	}
	if value.ManifestBytes == 0 {
		return errors.New("published manifest byte count must be greater than zero")
	}
	if value.ManifestBytes > MaxManifestBytes {
		return fmt.Errorf(
			"published manifest byte count exceeds %d bytes",
			MaxManifestBytes,
		)
	}
	if len(value.SignedBatch.Version) > MaxVersionBytes {
		return fmt.Errorf("signed batch version exceeds %d bytes", MaxVersionBytes)
	}
	if len(value.SignedBatch.Descriptor.Version) > MaxVersionBytes {
		return fmt.Errorf("descriptor version exceeds %d bytes", MaxVersionBytes)
	}
	if len(value.SignedBatch.Descriptor.SourceID) > MaxTextBytes {
		return fmt.Errorf("source ID exceeds %d bytes", MaxTextBytes)
	}
	if len(value.SignedBatch.Descriptor.BatchID) > MaxTextBytes {
		return fmt.Errorf("batch ID exceeds %d bytes", MaxTextBytes)
	}

	return nil
}

// WriteHeader writes exactly one deterministic FI wire header. The caller sends
// the exact manifest bytes next, followed by exactly Descriptor.DataBytes batch
// bytes. Payload streaming and durable receiver staging are separate contracts.
func WriteHeader(
	writer io.Writer,
	signedBatch transportpackage.SignedBatch,
	manifest []byte,
) error {
	if writer == nil {
		return errors.New("wire writer is required")
	}

	value, err := headerFromManifest(signedBatch, manifest)
	if err != nil {
		return fmt.Errorf("construct FI wire header: %w", err)
	}

	descriptor := value.SignedBatch.Descriptor
	dataDigest, err := hex.DecodeString(descriptor.DataSHA256)
	if err != nil {
		return fmt.Errorf("decode data SHA-256: %w", err)
	}
	manifestDigest, err := hex.DecodeString(descriptor.ManifestSHA256)
	if err != nil {
		return fmt.Errorf("decode manifest SHA-256: %w", err)
	}

	fixed := make([]byte, fixedHeaderBytes)
	copy(fixed[:8], frameMagic)
	binary.BigEndian.PutUint32(fixed[8:12], uint32(len(value.SignedBatch.Version)))
	binary.BigEndian.PutUint32(fixed[12:16], uint32(len(descriptor.Version)))
	binary.BigEndian.PutUint32(fixed[16:20], uint32(len(descriptor.SourceID)))
	binary.BigEndian.PutUint32(fixed[20:24], uint32(len(descriptor.BatchID)))
	binary.BigEndian.PutUint64(fixed[24:32], descriptor.RecordCount)
	binary.BigEndian.PutUint64(fixed[32:40], descriptor.DataBytes)
	binary.BigEndian.PutUint64(fixed[40:48], value.ManifestBytes)
	copy(fixed[48:80], dataDigest)
	copy(fixed[80:112], manifestDigest)
	binary.BigEndian.PutUint32(fixed[112:116], uint32(len(value.SignedBatch.Signature)))
	binary.BigEndian.PutUint32(
		fixed[116:120],
		uint32(len(value.SignedBatch.BatchSigningCertificateDER)),
	)

	var encoded bytes.Buffer
	encoded.Grow(
		fixedHeaderBytes +
			len(value.SignedBatch.Version) +
			len(descriptor.Version) +
			len(descriptor.SourceID) +
			len(descriptor.BatchID) +
			len(value.SignedBatch.Signature) +
			len(value.SignedBatch.BatchSigningCertificateDER),
	)
	encoded.Write(fixed)
	encoded.WriteString(value.SignedBatch.Version)
	encoded.WriteString(descriptor.Version)
	encoded.WriteString(descriptor.SourceID)
	encoded.WriteString(descriptor.BatchID)
	encoded.Write(value.SignedBatch.Signature)
	encoded.Write(value.SignedBatch.BatchSigningCertificateDER)

	if _, err := io.Copy(writer, &encoded); err != nil {
		return fmt.Errorf("write FI wire header: %w", err)
	}

	return nil
}

func cloneSignedBatch(value transportpackage.SignedBatch) transportpackage.SignedBatch {
	result := value
	result.Signature = append([]byte(nil), value.Signature...)
	result.BatchSigningCertificateDER = append(
		[]byte(nil),
		value.BatchSigningCertificateDER...,
	)
	return result
}

func readBytes(reader io.Reader, length uint32, name string) ([]byte, error) {
	value := make([]byte, int(length))
	if _, err := io.ReadFull(reader, value); err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return value, nil
}

func readString(reader io.Reader, length uint32, name string) (string, error) {
	value, err := readBytes(reader, length, name)
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func validateLengths(
	signedVersionBytes uint32,
	descriptorVersionBytes uint32,
	sourceIDBytes uint32,
	batchIDBytes uint32,
	signatureBytes uint32,
	certificateBytes uint32,
	manifestBytes uint64,
) error {
	if signedVersionBytes == 0 || signedVersionBytes > MaxVersionBytes {
		return fmt.Errorf("signed batch version length is invalid: %d", signedVersionBytes)
	}
	if descriptorVersionBytes == 0 || descriptorVersionBytes > MaxVersionBytes {
		return fmt.Errorf("descriptor version length is invalid: %d", descriptorVersionBytes)
	}
	if sourceIDBytes == 0 || sourceIDBytes > MaxTextBytes {
		return fmt.Errorf("source ID length is invalid: %d", sourceIDBytes)
	}
	if batchIDBytes == 0 || batchIDBytes > MaxTextBytes {
		return fmt.Errorf("batch ID length is invalid: %d", batchIDBytes)
	}
	if signatureBytes == 0 ||
		signatureBytes > transportpackage.MaxBatchSignatureBytes {
		return fmt.Errorf("batch signature length is invalid: %d", signatureBytes)
	}
	if certificateBytes == 0 ||
		certificateBytes > transportpackage.MaxBatchSigningCertificateDERBytes {
		return fmt.Errorf(
			"batch-signing certificate DER length is invalid: %d",
			certificateBytes,
		)
	}
	if manifestBytes == 0 || manifestBytes > MaxManifestBytes {
		return fmt.Errorf("published manifest length is invalid: %d", manifestBytes)
	}

	return nil
}
