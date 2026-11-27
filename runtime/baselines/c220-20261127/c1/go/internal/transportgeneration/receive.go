// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportgeneration

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

const (
	generationCanonicalMagic = "FI-GENERATION-CANONICAL-V1\x00"

	generationCanonicalChunkBytes = 1024 * 1024

	maxReceiveArtifactCount = 1_000_000

	maxCanonicalArtifactNameBytes = 4096
)

type ReceiveConfig struct {
	BatchCRL    *x509.RevocationList
	BatchIssuer *x509.Certificate
	CurrentTime time.Time

	MaxCanonicalBytes uint64
	MaxEncodedBytes   uint64

	Root   *x509.Certificate
	Source transporttrust.SourceAuthorization
}

// ReadValidatedTransfer consumes exactly one FIGT0001 generation transfer.
//
// The encoded payload is read once. During that same read FI:
//
//   - computes the exact transfer SHA-256;
//   - computes the encoded payload SHA-256;
//   - decompresses with FI's bounded zstd decoder;
//   - validates the canonical generation framing;
//   - computes the canonical SHA-256 and byte count; and
//   - verifies artifact/source byte counts.
//
// This layer does not interpret manifests, JSONL records, batch IDs, or any
// other collector semantics.
func ReadValidatedTransfer(
	reader io.Reader,
	offer Offer,
	config ReceiveConfig,
) (
	TransferResult,
	error,
) {
	return readValidatedTransfer(
		reader,
		offer,
		config,
		nil,
	)
}

func readValidatedTransfer(
	reader io.Reader,
	offer Offer,
	config ReceiveConfig,
	handler CanonicalArtifactHandler,
) (
	TransferResult,
	error,
) {
	if reader == nil {
		return TransferResult{},
			errors.New(
				"FI generation transfer reader is required",
			)
	}

	if err :=
		offer.Validate(); err != nil {
		return TransferResult{},
			fmt.Errorf(
				"validate FI generation offer before transfer: %w",
				err,
			)
	}

	if err :=
		validateReceiveConfig(
			config,
		); err != nil {
		return TransferResult{}, err
	}

	descriptor :=
		offer.Descriptor

	if descriptor.SourceID !=
		config.Source.SourceID {
		return TransferResult{},
			fmt.Errorf(
				"FI generation source ID %q does not match enrolled source %q",
				descriptor.SourceID,
				config.Source.SourceID,
			)
	}

	if descriptor.ArtifactCount >
		maxReceiveArtifactCount {
		return TransferResult{},
			fmt.Errorf(
				"FI generation artifact count %d exceeds structural safety limit %d",
				descriptor.ArtifactCount,
				maxReceiveArtifactCount,
			)
	}

	if descriptor.CanonicalBytes >
		config.MaxCanonicalBytes {
		return TransferResult{},
			fmt.Errorf(
				"FI generation canonical bytes %d exceed receiver limit %d",
				descriptor.CanonicalBytes,
				config.MaxCanonicalBytes,
			)
	}

	if descriptor.EncodedDataBytes >
		config.MaxEncodedBytes {
		return TransferResult{},
			fmt.Errorf(
				"FI generation encoded bytes %d exceed receiver limit %d",
				descriptor.EncodedDataBytes,
				config.MaxEncodedBytes,
			)
	}

	transferHasher :=
		sha256.New()

	transferCounter :=
		&generationCountWriter{}

	transferReader :=
		io.TeeReader(
			reader,
			io.MultiWriter(
				transferHasher,
				transferCounter,
			),
		)

	var header [transferHeaderBytes]byte

	if _,
		err :=
		io.ReadFull(
			transferReader,
			header[:],
		); err != nil {
		return TransferResult{},
			fmt.Errorf(
				"read FI generation transfer header: %w",
				err,
			)
	}

	if string(
		header[0:8],
	) != TransferMagic {
		return TransferResult{},
			errors.New(
				"unexpected FI generation transfer magic",
			)
	}

	metadataBytes :=
		uint64(
			binary.BigEndian.Uint32(
				header[8:12],
			),
		)

	payloadBytes :=
		binary.BigEndian.Uint64(
			header[12:20],
		)

	if metadataBytes !=
		offer.MetadataBytes {
		return TransferResult{},
			errors.New(
				"FI generation transfer metadata byte count does not match offer",
			)
	}

	if payloadBytes !=
		descriptor.EncodedDataBytes {
		return TransferResult{},
			errors.New(
				"FI generation transfer payload byte count does not match signed descriptor",
			)
	}

	if metadataBytes == 0 ||
		metadataBytes >
			uint64(
				maxSignedGenerationMetadataBytes,
			) {
		return TransferResult{},
			errors.New(
				"FI generation transfer metadata byte count is outside bounds",
			)
	}

	metadata :=
		make(
			[]byte,
			int(metadataBytes),
		)

	if _,
		err :=
		io.ReadFull(
			transferReader,
			metadata,
		); err != nil {
		return TransferResult{},
			fmt.Errorf(
				"read FI generation transfer metadata: %w",
				err,
			)
	}

	metadataDigest :=
		sha256.Sum256(
			metadata,
		)

	metadataSHA :=
		hex.EncodeToString(
			metadataDigest[:],
		)

	if metadataSHA !=
		offer.MetadataSHA256 {
		return TransferResult{},
			errors.New(
				"FI generation transfer metadata SHA-256 does not match offer",
			)
	}

	signed, err :=
		UnmarshalSignedGeneration(
			metadata,
		)
	if err != nil {
		return TransferResult{},
			fmt.Errorf(
				"validate signed FI generation metadata: %w",
				err,
			)
	}

	if signed.Descriptor !=
		descriptor {
		return TransferResult{},
			errors.New(
				"FI generation transfer metadata descriptor does not match offer",
			)
	}

	certificate, err :=
		signed.BatchSigningCertificate()
	if err != nil {
		return TransferResult{}, err
	}

	outcome, err :=
		transporttrust.VerifyBatchSigningCertificate(
			certificate,
			config.Root,
			config.BatchIssuer,
			config.BatchCRL,
			config.Source,
			config.CurrentTime,
		)
	if err != nil {
		return TransferResult{},
			fmt.Errorf(
				"authorize FI generation batch-signing certificate: %w",
				err,
			)
	}

	if outcome !=
		transporttrust.AuthorizationAuthorized {
		return TransferResult{},
			fmt.Errorf(
				"FI generation batch-signing authorization rejected: %s",
				outcome,
			)
	}

	limited :=
		&io.LimitedReader{
			R: transferReader,

			N: int64(
				payloadBytes,
			),
		}

	encodedHasher :=
		sha256.New()

	decoder, err :=
		transportencoding.NewZstdDecoder(
			io.TeeReader(
				limited,
				encodedHasher,
			),
		)
	if err != nil {
		return TransferResult{}, err
	}

	canonicalHasher :=
		sha256.New()

	canonicalCounter :=
		&generationCountWriter{}

	canonicalReader :=
		io.TeeReader(
			decoder,
			io.MultiWriter(
				canonicalHasher,
				canonicalCounter,
			),
		)

	sourceBytes, err :=
		ReadCanonicalArtifacts(
			canonicalReader,
			descriptor,
			handler,
		)

	if err != nil {
		decoder.Close()

		return TransferResult{},
			fmt.Errorf(
				"validate FI generation canonical payload: %w",
				err,
			)
	}

	var extra [1]byte

	n, extraErr :=
		canonicalReader.Read(
			extra[:],
		)

	decoder.Close()

	if n != 0 ||
		!errors.Is(
			extraErr,
			io.EOF,
		) {
		return TransferResult{},
			errors.New(
				"FI generation canonical payload contains trailing decoded bytes",
			)
	}

	if limited.N != 0 {
		return TransferResult{},
			errors.New(
				"FI generation encoded payload contains unread bytes",
			)
	}

	if sourceBytes !=
		descriptor.SourceBytes {
		return TransferResult{},
			fmt.Errorf(
				"FI generation source byte count %d does not match signed descriptor %d",
				sourceBytes,
				descriptor.SourceBytes,
			)
	}

	if canonicalCounter.bytes !=
		descriptor.CanonicalBytes {
		return TransferResult{},
			fmt.Errorf(
				"FI generation canonical byte count %d does not match signed descriptor %d",
				canonicalCounter.bytes,
				descriptor.CanonicalBytes,
			)
	}

	canonicalSHA :=
		hex.EncodeToString(
			canonicalHasher.Sum(
				nil,
			),
		)

	if canonicalSHA !=
		descriptor.CanonicalSHA256 {
		return TransferResult{},
			errors.New(
				"FI generation canonical SHA-256 does not match signed descriptor",
			)
	}

	encodedSHA :=
		hex.EncodeToString(
			encodedHasher.Sum(
				nil,
			),
		)

	if encodedSHA !=
		descriptor.EncodedDataSHA256 {
		return TransferResult{},
			errors.New(
				"FI generation encoded SHA-256 does not match signed descriptor",
			)
	}

	expectedTransferBytes :=
		uint64(
			transferHeaderBytes,
		)

	if metadataBytes >
		^uint64(0)-
			expectedTransferBytes {
		return TransferResult{},
			errors.New(
				"FI generation transfer byte count overflow",
			)
	}

	expectedTransferBytes +=
		metadataBytes

	if payloadBytes >
		^uint64(0)-
			expectedTransferBytes {
		return TransferResult{},
			errors.New(
				"FI generation transfer byte count overflow",
			)
	}

	expectedTransferBytes +=
		payloadBytes

	if transferCounter.bytes !=
		expectedTransferBytes {
		return TransferResult{},
			fmt.Errorf(
				"FI generation transfer byte count %d does not match expected %d",
				transferCounter.bytes,
				expectedTransferBytes,
			)
	}

	return TransferResult{
		Descriptor: descriptor,

		MetadataBytes: metadataBytes,

		MetadataSHA256: metadataSHA,

		PayloadBytes: payloadBytes,

		PayloadSHA256: encodedSHA,

		TransferBytes: transferCounter.bytes,

		TransferSHA256: hex.EncodeToString(
			transferHasher.Sum(
				nil,
			),
		),
	}, nil
}

func readCanonicalGeneration(
	reader io.Reader,
	descriptor Descriptor,
) (
	uint64,
	error,
) {
	return ReadCanonicalArtifacts(
		reader,
		descriptor,
		nil,
	)
}

func validateReceiveConfig(
	config ReceiveConfig,
) error {
	if config.BatchCRL == nil {
		return errors.New(
			"FI generation batch-signing CRL is required",
		)
	}

	if config.BatchIssuer == nil {
		return errors.New(
			"FI generation batch-signing issuer is required",
		)
	}

	if config.CurrentTime.IsZero() {
		return errors.New(
			"FI generation receiver current time is required",
		)
	}

	if config.MaxCanonicalBytes == 0 ||
		config.MaxCanonicalBytes >
			uint64(
				1<<63-1,
			) {
		return errors.New(
			"FI generation maximum canonical byte count is outside bounds",
		)
	}

	if config.MaxEncodedBytes == 0 ||
		config.MaxEncodedBytes >
			uint64(
				1<<63-1,
			) {
		return errors.New(
			"FI generation maximum encoded byte count is outside bounds",
		)
	}

	if config.Root == nil {
		return errors.New(
			"FI generation root certificate is required",
		)
	}

	if err :=
		validateTextIdentity(
			"source ID",
			config.Source.SourceID,
		); err != nil {
		return err
	}

	return nil
}
