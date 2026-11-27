// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportgeneration

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	TransferMagic = "FIGT0001"

	transferHeaderBytes = 20
)

type TransferResult struct {
	Descriptor Descriptor

	MetadataBytes  uint64
	MetadataSHA256 string

	PayloadBytes  uint64
	PayloadSHA256 string

	TransferBytes  uint64
	TransferSHA256 string
}

// WritePublishedGeneration streams one already-published generation.
//
// The metadata and payload are read directly from the durable generation
// object. They are not re-marshaled, recompressed or rebuilt.
//
// Wire layout:
//
//	8 bytes   magic
//	4 bytes   signed metadata length, big endian
//	8 bytes   encoded payload length, big endian
//	N bytes   exact signed-generation.json bytes
//	M bytes   exact payload.figz bytes
//
// The signed descriptor remains authoritative for payload identity. The wire
// header is framing only and is deliberately not a second representation of
// generation semantics.
func WritePublishedGeneration(
	writer io.Writer,
	generation PublishedGeneration,
) (
	TransferResult,
	error,
) {
	if writer == nil {
		return TransferResult{},
			errors.New(
				"FI generation transport writer is required",
			)
	}

	if generation.DirectoryPath == "" ||
		generation.MetadataPath == "" ||
		generation.PayloadPath == "" {
		return TransferResult{},
			errors.New(
				"FI published generation paths are incomplete",
			)
	}

	current, err :=
		LoadSealedGeneration(
			generation.DirectoryPath,
		)
	if err != nil {
		return TransferResult{},
			fmt.Errorf(
				"reload FI generation before transport: %w",
				err,
			)
	}

	if current.MetadataPath !=
		generation.MetadataPath ||
		current.PayloadPath !=
			generation.PayloadPath ||
		!signedGenerationsEqual(
			current.Signed,
			generation.Signed,
		) {
		return TransferResult{},
			errors.New(
				"FI published generation changed before transport",
			)
	}

	metadata, err :=
		readStableBoundedGenerationFile(
			current.MetadataPath,
			maxSignedGenerationMetadataBytes,
		)
	if err != nil {
		return TransferResult{},
			fmt.Errorf(
				"read exact FI generation metadata for transport: %w",
				err,
			)
	}

	decoded, err :=
		UnmarshalSignedGeneration(
			metadata,
		)
	if err != nil {
		return TransferResult{}, err
	}

	if !signedGenerationsEqual(
		decoded,
		current.Signed,
	) {
		return TransferResult{},
			errors.New(
				"FI generation metadata bytes changed after durable discovery",
			)
	}

	if uint64(len(metadata)) >
		uint64(
			^uint32(0),
		) {
		return TransferResult{},
			errors.New(
				"FI generation metadata exceeds wire framing range",
			)
	}

	descriptor :=
		current.Signed.Descriptor

	initial, err :=
		os.Lstat(
			current.PayloadPath,
		)
	if err != nil {
		return TransferResult{}, err
	}

	if initial.Mode()&
		os.ModeSymlink != 0 ||
		!initial.Mode().IsRegular() ||
		initial.Size() <= 0 ||
		uint64(initial.Size()) !=
			descriptor.EncodedDataBytes {
		return TransferResult{},
			errors.New(
				"FI generation payload changed before transport",
			)
	}

	payload, err :=
		os.Open(
			current.PayloadPath,
		)
	if err != nil {
		return TransferResult{}, err
	}

	opened, err :=
		payload.Stat()
	if err != nil {
		_ = payload.Close()
		return TransferResult{}, err
	}

	if !os.SameFile(
		initial,
		opened,
	) {
		_ = payload.Close()

		return TransferResult{},
			errors.New(
				"FI generation payload changed while opening for transport",
			)
	}

	var header [transferHeaderBytes]byte

	copy(
		header[0:8],
		[]byte(
			TransferMagic,
		),
	)

	binary.BigEndian.PutUint32(
		header[8:12],
		uint32(
			len(metadata),
		),
	)

	binary.BigEndian.PutUint64(
		header[12:20],
		descriptor.EncodedDataBytes,
	)

	transferHasher :=
		sha256.New()

	transferCounter :=
		&generationCountWriter{}

	transportWriter :=
		io.MultiWriter(
			writer,
			transferHasher,
			transferCounter,
		)

	if _,
		err :=
		transportWriter.Write(
			header[:],
		); err != nil {
		_ = payload.Close()

		return TransferResult{},
			fmt.Errorf(
				"write FI generation transport header: %w",
				err,
			)
	}

	if _,
		err :=
		transportWriter.Write(
			metadata,
		); err != nil {
		_ = payload.Close()

		return TransferResult{},
			fmt.Errorf(
				"write exact FI generation metadata: %w",
				err,
			)
	}

	payloadHasher :=
		sha256.New()

	written, copyErr :=
		io.CopyN(
			io.MultiWriter(
				transportWriter,
				payloadHasher,
			),
			payload,
			int64(
				descriptor.EncodedDataBytes,
			),
		)

	if copyErr != nil {
		_ = payload.Close()

		return TransferResult{},
			fmt.Errorf(
				"stream exact FI generation payload: %w",
				copyErr,
			)
	}

	if uint64(written) !=
		descriptor.EncodedDataBytes {
		_ = payload.Close()

		return TransferResult{},
			errors.New(
				"FI generation payload transport was short",
			)
	}

	var trailing [1]byte

	n, trailingErr :=
		payload.Read(
			trailing[:],
		)

	closeErr :=
		payload.Close()

	if n != 0 ||
		!errors.Is(
			trailingErr,
			io.EOF,
		) {
		return TransferResult{},
			errors.New(
				"FI generation payload contains unexpected trailing bytes",
			)
	}

	if closeErr != nil {
		return TransferResult{},
			closeErr
	}

	after, err :=
		os.Lstat(
			current.PayloadPath,
		)
	if err != nil {
		return TransferResult{}, err
	}

	if !os.SameFile(
		opened,
		after,
	) ||
		after.Size() !=
			initial.Size() {
		return TransferResult{},
			errors.New(
				"FI generation payload changed during transport",
			)
	}

	payloadSHA :=
		hex.EncodeToString(
			payloadHasher.Sum(
				nil,
			),
		)

	if payloadSHA !=
		descriptor.EncodedDataSHA256 {
		return TransferResult{},
			errors.New(
				"FI generation payload SHA-256 changed during transport",
			)
	}

	metadataDigest :=
		sha256.Sum256(
			metadata,
		)

	return TransferResult{
		Descriptor: descriptor,

		MetadataBytes: uint64(
			len(metadata),
		),

		MetadataSHA256: hex.EncodeToString(
			metadataDigest[:],
		),

		PayloadBytes: descriptor.EncodedDataBytes,

		PayloadSHA256: payloadSHA,

		TransferBytes: transferCounter.bytes,

		TransferSHA256: hex.EncodeToString(
			transferHasher.Sum(
				nil,
			),
		),
	}, nil
}

func signedGenerationsEqual(
	left SignedGeneration,
	right SignedGeneration,
) bool {
	return left.Version ==
		right.Version &&
		left.Descriptor ==
			right.Descriptor &&
		bytes.Equal(
			left.Signature,
			right.Signature,
		) &&
		bytes.Equal(
			left.BatchSigningCertificateDER,
			right.BatchSigningCertificateDER,
		)
}
