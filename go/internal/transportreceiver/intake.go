// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportreceiver

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportwire"
)

const maxCopyDataBytes = uint64(1<<63 - 1)

// IntakeConfig defines the trust and resource bounds required to validate one
// framed FI batch after the transport connection itself has been authenticated.
type IntakeConfig struct {
	BatchCRL     *x509.RevocationList
	BatchIssuer  *x509.Certificate
	CurrentTime  time.Time
	MaxDataBytes uint64
	Root         *x509.Certificate
	Source       transporttrust.SourceAuthorization
}

// IntakeResult describes one completely read and validated FI wire batch.
//
// This result does not establish durable backend custody and must not be used as
// a transport acknowledgement. Data written to the supplied writer is
// provisional until ReadValidatedBatch returns success.
type IntakeResult struct {
	DataBytes  uint64
	DataSHA256 string
	Header     transportwire.Header
	Manifest   []byte
}

// ReadValidatedBatch reads exactly one framed FI batch from reader, verifies its
// enrolled Batch Signing identity and signature, verifies the exact manifest and
// data hashes, and streams exactly Descriptor.DataBytes bytes to dataWriter.
//
// The function intentionally does not read beyond the current batch. A caller
// may therefore leave a subsequent frame on the same stream for later work.
// Successful return proves bounded intake and package integrity only; durable
// staging and durable acknowledgement are separate Phase 2 contracts.
func ReadValidatedBatch(
	reader io.Reader,
	dataWriter io.Writer,
	config IntakeConfig,
) (IntakeResult, error) {
	if reader == nil {
		return IntakeResult{}, errors.New("batch reader is required")
	}
	if dataWriter == nil {
		return IntakeResult{}, errors.New("batch data writer is required")
	}
	if err := validateIntakeConfig(config); err != nil {
		return IntakeResult{}, err
	}

	header, err := transportwire.ReadHeader(reader)
	if err != nil {
		return IntakeResult{}, fmt.Errorf("read FI batch wire header: %w", err)
	}

	descriptor := header.SignedBatch.Descriptor
	if descriptor.DataBytes > config.MaxDataBytes {
		return IntakeResult{}, fmt.Errorf(
			"batch data byte count %d exceeds receiver limit %d",
			descriptor.DataBytes,
			config.MaxDataBytes,
		)
	}
	if descriptor.DataBytes > maxCopyDataBytes {
		return IntakeResult{}, fmt.Errorf(
			"batch data byte count %d exceeds supported streaming range",
			descriptor.DataBytes,
		)
	}

	certificate, err := header.SignedBatch.BatchSigningCertificate()
	if err != nil {
		return IntakeResult{}, fmt.Errorf(
			"parse FI batch-signing certificate: %w",
			err,
		)
	}

	outcome, err := transporttrust.VerifySignedBatch(
		descriptor,
		header.SignedBatch.Signature,
		certificate,
		config.Root,
		config.BatchIssuer,
		config.BatchCRL,
		config.Source,
		config.CurrentTime,
	)
	if err != nil {
		return IntakeResult{}, fmt.Errorf("verify signed FI batch: %w", err)
	}
	if outcome != transporttrust.AuthorizationAuthorized {
		return IntakeResult{}, fmt.Errorf(
			"FI batch-signing authorization rejected: %s",
			outcome,
		)
	}

	manifest := make([]byte, int(header.ManifestBytes))
	if _, err := io.ReadFull(reader, manifest); err != nil {
		return IntakeResult{}, fmt.Errorf(
			"read published FI batch manifest payload: %w",
			err,
		)
	}
	manifestDigest := sha256.Sum256(manifest)
	manifestSHA256 := hex.EncodeToString(manifestDigest[:])
	if manifestSHA256 != descriptor.ManifestSHA256 {
		return IntakeResult{}, errors.New(
			"published FI batch manifest SHA-256 does not match signed descriptor",
		)
	}

	dataHasher := sha256.New()
	written, err := io.CopyN(
		io.MultiWriter(dataWriter, dataHasher),
		reader,
		int64(descriptor.DataBytes),
	)
	if err != nil {
		return IntakeResult{}, fmt.Errorf("read FI batch data payload: %w", err)
	}
	if uint64(written) != descriptor.DataBytes {
		return IntakeResult{}, fmt.Errorf(
			"read FI batch data payload: wrote %d bytes, want %d",
			written,
			descriptor.DataBytes,
		)
	}

	dataSHA256 := hex.EncodeToString(dataHasher.Sum(nil))
	if dataSHA256 != descriptor.DataSHA256 {
		return IntakeResult{}, errors.New(
			"FI batch data SHA-256 does not match signed descriptor",
		)
	}

	return IntakeResult{
		DataBytes:  descriptor.DataBytes,
		DataSHA256: dataSHA256,
		Header:     header,
		Manifest:   append([]byte(nil), manifest...),
	}, nil
}

func validateIntakeConfig(config IntakeConfig) error {
	if config.BatchCRL == nil {
		return errors.New("batch-signing CRL is required")
	}
	if config.BatchIssuer == nil {
		return errors.New("batch-signing issuing certificate is required")
	}
	if config.CurrentTime.IsZero() {
		return errors.New("current time is required")
	}
	if config.MaxDataBytes == 0 {
		return errors.New("maximum batch data byte count must be greater than zero")
	}
	if config.Root == nil {
		return errors.New("FI root certificate is required")
	}
	if config.Source.SourceID == "" {
		return errors.New("FI source authorization is required")
	}

	return nil
}
