// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportwire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportbatch"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportpackage"
)

const (
	fixedHeaderBytesV2 = 164
	frameMagicV2       = "FIWB0002"

	MaxDataEncodingBytes = 32
)

// ReadHeaderV2 reads exactly one bounded FI 0.2 wire header. It stops before
// the published manifest payload, leaving the reader positioned at its first
// byte.
//
// The caller must subsequently consume Header.ManifestBytes manifest bytes and
// exactly Descriptor.EncodedDataBytes encoded data bytes.
func ReadHeaderV2(reader io.Reader) (Header, error) {
	if reader == nil {
		return Header{}, errors.New("wire reader is required")
	}

	fixed := make([]byte, fixedHeaderBytesV2)
	if _, err := io.ReadFull(reader, fixed); err != nil {
		return Header{}, fmt.Errorf("read FI wire 0.2 fixed header: %w", err)
	}
	if string(fixed[:len(frameMagicV2)]) != frameMagicV2 {
		return Header{}, errors.New("FI wire 0.2 frame magic is invalid")
	}

	signedVersionBytes := binary.BigEndian.Uint32(fixed[8:12])
	descriptorVersionBytes := binary.BigEndian.Uint32(fixed[12:16])
	sourceIDBytes := binary.BigEndian.Uint32(fixed[16:20])
	batchIDBytes := binary.BigEndian.Uint32(fixed[20:24])
	dataEncodingBytes := binary.BigEndian.Uint32(fixed[24:28])
	recordCount := binary.BigEndian.Uint64(fixed[28:36])
	dataBytes := binary.BigEndian.Uint64(fixed[36:44])
	encodedDataBytes := binary.BigEndian.Uint64(fixed[44:52])
	manifestBytes := binary.BigEndian.Uint64(fixed[52:60])
	dataSHA256 := hex.EncodeToString(fixed[60:92])
	encodedDataSHA256 := hex.EncodeToString(fixed[92:124])
	manifestSHA256 := hex.EncodeToString(fixed[124:156])
	signatureBytes := binary.BigEndian.Uint32(fixed[156:160])
	certificateBytes := binary.BigEndian.Uint32(fixed[160:164])

	if err := validateLengthsV2(
		signedVersionBytes,
		descriptorVersionBytes,
		sourceIDBytes,
		batchIDBytes,
		dataEncodingBytes,
		signatureBytes,
		certificateBytes,
		manifestBytes,
	); err != nil {
		return Header{}, err
	}

	signedVersion, err := readString(
		reader,
		signedVersionBytes,
		"signed batch version",
	)
	if err != nil {
		return Header{}, err
	}
	descriptorVersion, err := readString(
		reader,
		descriptorVersionBytes,
		"descriptor version",
	)
	if err != nil {
		return Header{}, err
	}
	if descriptorVersion != transportbatch.DescriptorVersionV2 {
		return Header{}, fmt.Errorf(
			"FI wire 0.2 requires descriptor version %q, got %q",
			transportbatch.DescriptorVersionV2,
			descriptorVersion,
		)
	}
	sourceID, err := readString(reader, sourceIDBytes, "source ID")
	if err != nil {
		return Header{}, err
	}
	batchID, err := readString(reader, batchIDBytes, "batch ID")
	if err != nil {
		return Header{}, err
	}
	dataEncoding, err := readString(
		reader,
		dataEncodingBytes,
		"data encoding",
	)
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
				Version:           descriptorVersion,
				SourceID:          sourceID,
				BatchID:           batchID,
				RecordCount:       recordCount,
				DataBytes:         dataBytes,
				DataSHA256:        dataSHA256,
				DataEncoding:      dataEncoding,
				EncodedDataBytes:  encodedDataBytes,
				EncodedDataSHA256: encodedDataSHA256,
				ManifestSHA256:    manifestSHA256,
			},
			Signature:                  signature,
			BatchSigningCertificateDER: certificateDER,
		},
		ManifestBytes: manifestBytes,
	}
	if err := value.Validate(); err != nil {
		return Header{}, fmt.Errorf("validate FI wire 0.2 header: %w", err)
	}

	return value, nil
}

// WriteHeaderV2 writes exactly one deterministic FI 0.2 wire header. The
// caller sends the exact manifest bytes next, followed by exactly
// Descriptor.EncodedDataBytes encoded bytes.
//
// Canonical DataBytes and DataSHA256 remain signed logical facts. The encoded
// count and hash bind the separate zstd representation that actually crosses
// the transport.
func WriteHeaderV2(
	writer io.Writer,
	signedBatch transportpackage.SignedBatch,
	manifest []byte,
) error {
	if writer == nil {
		return errors.New("wire writer is required")
	}
	if signedBatch.Descriptor.Version != transportbatch.DescriptorVersionV2 {
		return fmt.Errorf(
			"FI wire 0.2 requires descriptor version %q",
			transportbatch.DescriptorVersionV2,
		)
	}

	value, err := headerFromManifest(signedBatch, manifest)
	if err != nil {
		return fmt.Errorf("construct FI wire 0.2 header: %w", err)
	}

	descriptor := value.SignedBatch.Descriptor
	dataDigest, err := hex.DecodeString(descriptor.DataSHA256)
	if err != nil {
		return fmt.Errorf("decode data SHA-256: %w", err)
	}
	encodedDataDigest, err := hex.DecodeString(descriptor.EncodedDataSHA256)
	if err != nil {
		return fmt.Errorf("decode encoded data SHA-256: %w", err)
	}
	manifestDigest, err := hex.DecodeString(descriptor.ManifestSHA256)
	if err != nil {
		return fmt.Errorf("decode manifest SHA-256: %w", err)
	}

	fixed := make([]byte, fixedHeaderBytesV2)
	copy(fixed[:8], frameMagicV2)
	binary.BigEndian.PutUint32(
		fixed[8:12],
		uint32(len(value.SignedBatch.Version)),
	)
	binary.BigEndian.PutUint32(
		fixed[12:16],
		uint32(len(descriptor.Version)),
	)
	binary.BigEndian.PutUint32(
		fixed[16:20],
		uint32(len(descriptor.SourceID)),
	)
	binary.BigEndian.PutUint32(
		fixed[20:24],
		uint32(len(descriptor.BatchID)),
	)
	binary.BigEndian.PutUint32(
		fixed[24:28],
		uint32(len(descriptor.DataEncoding)),
	)
	binary.BigEndian.PutUint64(fixed[28:36], descriptor.RecordCount)
	binary.BigEndian.PutUint64(fixed[36:44], descriptor.DataBytes)
	binary.BigEndian.PutUint64(fixed[44:52], descriptor.EncodedDataBytes)
	binary.BigEndian.PutUint64(fixed[52:60], value.ManifestBytes)
	copy(fixed[60:92], dataDigest)
	copy(fixed[92:124], encodedDataDigest)
	copy(fixed[124:156], manifestDigest)
	binary.BigEndian.PutUint32(
		fixed[156:160],
		uint32(len(value.SignedBatch.Signature)),
	)
	binary.BigEndian.PutUint32(
		fixed[160:164],
		uint32(len(value.SignedBatch.BatchSigningCertificateDER)),
	)

	var encoded bytes.Buffer
	encoded.Grow(
		fixedHeaderBytesV2 +
			len(value.SignedBatch.Version) +
			len(descriptor.Version) +
			len(descriptor.SourceID) +
			len(descriptor.BatchID) +
			len(descriptor.DataEncoding) +
			len(value.SignedBatch.Signature) +
			len(value.SignedBatch.BatchSigningCertificateDER),
	)
	encoded.Write(fixed)
	encoded.WriteString(value.SignedBatch.Version)
	encoded.WriteString(descriptor.Version)
	encoded.WriteString(descriptor.SourceID)
	encoded.WriteString(descriptor.BatchID)
	encoded.WriteString(descriptor.DataEncoding)
	encoded.Write(value.SignedBatch.Signature)
	encoded.Write(value.SignedBatch.BatchSigningCertificateDER)

	if _, err := io.Copy(writer, &encoded); err != nil {
		return fmt.Errorf("write FI wire 0.2 header: %w", err)
	}

	return nil
}

func validateLengthsV2(
	signedVersionBytes uint32,
	descriptorVersionBytes uint32,
	sourceIDBytes uint32,
	batchIDBytes uint32,
	dataEncodingBytes uint32,
	signatureBytes uint32,
	certificateBytes uint32,
	manifestBytes uint64,
) error {
	if signedVersionBytes == 0 || signedVersionBytes > MaxVersionBytes {
		return fmt.Errorf(
			"signed batch version length is invalid: %d",
			signedVersionBytes,
		)
	}
	if descriptorVersionBytes == 0 ||
		descriptorVersionBytes > MaxVersionBytes {
		return fmt.Errorf(
			"descriptor version length is invalid: %d",
			descriptorVersionBytes,
		)
	}
	if sourceIDBytes == 0 || sourceIDBytes > MaxTextBytes {
		return fmt.Errorf("source ID length is invalid: %d", sourceIDBytes)
	}
	if batchIDBytes == 0 || batchIDBytes > MaxTextBytes {
		return fmt.Errorf("batch ID length is invalid: %d", batchIDBytes)
	}
	if dataEncodingBytes == 0 ||
		dataEncodingBytes > MaxDataEncodingBytes {
		return fmt.Errorf(
			"data encoding length is invalid: %d",
			dataEncodingBytes,
		)
	}
	if signatureBytes == 0 ||
		signatureBytes > transportpackage.MaxBatchSignatureBytes {
		return fmt.Errorf(
			"batch signature length is invalid: %d",
			signatureBytes,
		)
	}
	if certificateBytes == 0 ||
		certificateBytes >
			transportpackage.MaxBatchSigningCertificateDERBytes {
		return fmt.Errorf(
			"batch-signing certificate DER length is invalid: %d",
			certificateBytes,
		)
	}
	if manifestBytes == 0 || manifestBytes > MaxManifestBytes {
		return fmt.Errorf(
			"published manifest length is invalid: %d",
			manifestBytes,
		)
	}

	return nil
}
