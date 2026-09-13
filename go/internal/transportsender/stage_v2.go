// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportbatch"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportencoding"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportpackage"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportwire"
)

const (
	outboundFrameMagicV1 = "FIWB0001"
	outboundFrameMagicV2 = "FIWB0002"
)

type outboundEncodedPayload struct {
	file           *os.File
	path           string
	representation transportbatch.EncodedRepresentation
}

func createOutboundEncodedPayload(
	config OutboundFrameConfig,
	canonical transportbatch.Descriptor,
) (outboundEncodedPayload, error) {
	if canonical.Version != transportbatch.DescriptorVersion {
		return outboundEncodedPayload{}, fmt.Errorf(
			"canonical FI outbound descriptor version must be %q, got %q",
			transportbatch.DescriptorVersion,
			canonical.Version,
		)
	}
	if canonical.DataBytes > maxOutboundCopyDataBytes {
		return outboundEncodedPayload{}, fmt.Errorf(
			"FI outbound data byte count %d exceeds supported streaming range",
			canonical.DataBytes,
		)
	}

	dataPath, err := outboundPublishedDataPath(config.ManifestPath, canonical.BatchID)
	if err != nil {
		return outboundEncodedPayload{}, err
	}
	data, err := openOutboundData(dataPath)
	if err != nil {
		return outboundEncodedPayload{}, err
	}
	defer data.Close()

	encoded, err := os.CreateTemp(config.StageDir, ".fi-encoded-*.open")
	if err != nil {
		return outboundEncodedPayload{}, fmt.Errorf(
			"create provisional FI encoded payload: %w",
			err,
		)
	}
	encodedPath := encoded.Name()
	encodedOpen := true
	keepEncoded := false
	defer func() {
		if encodedOpen {
			_ = encoded.Close()
		}
		if !keepEncoded {
			_ = os.Remove(encodedPath)
		}
	}()

	encodedHasher := sha256.New()
	encodedCounter := &outboundCountWriter{}
	encoder, err := transportencoding.NewZstdEncoder(
		io.MultiWriter(encoded, encodedHasher, encodedCounter),
	)
	if err != nil {
		return outboundEncodedPayload{}, fmt.Errorf(
			"create FI outbound zstd encoder: %w",
			err,
		)
	}

	canonicalHasher := sha256.New()
	written, copyErr := io.CopyN(
		encoder,
		io.TeeReader(data, canonicalHasher),
		int64(canonical.DataBytes),
	)
	closeErr := encoder.Close()
	if copyErr != nil {
		return outboundEncodedPayload{}, fmt.Errorf(
			"compress FI outbound data payload: %w",
			copyErr,
		)
	}
	if closeErr != nil {
		return outboundEncodedPayload{}, fmt.Errorf(
			"finalize FI outbound zstd payload: %w",
			closeErr,
		)
	}
	if uint64(written) != canonical.DataBytes {
		return outboundEncodedPayload{}, fmt.Errorf(
			"compress FI outbound data payload: read %d bytes, want %d",
			written,
			canonical.DataBytes,
		)
	}
	if err := ensureOutboundDataEOF(data); err != nil {
		return outboundEncodedPayload{}, err
	}
	if hex.EncodeToString(canonicalHasher.Sum(nil)) != canonical.DataSHA256 {
		return outboundEncodedPayload{}, errors.New(
			"published FI data changed while outbound payload was being compressed",
		)
	}
	if encodedCounter.bytes == 0 {
		return outboundEncodedPayload{}, errors.New(
			"FI outbound zstd payload must contain at least one byte",
		)
	}
	if encodedCounter.bytes > maxOutboundCopyDataBytes {
		return outboundEncodedPayload{}, fmt.Errorf(
			"FI outbound encoded byte count %d exceeds supported streaming range",
			encodedCounter.bytes,
		)
	}

	representation := transportbatch.EncodedRepresentation{
		DataEncoding:      transportencoding.DataEncodingZstd,
		EncodedDataBytes:  encodedCounter.bytes,
		EncodedDataSHA256: hex.EncodeToString(encodedHasher.Sum(nil)),
	}
	if err := representation.Validate(); err != nil {
		return outboundEncodedPayload{}, fmt.Errorf(
			"validate FI outbound encoded representation: %w",
			err,
		)
	}

	if err := encoded.Sync(); err != nil {
		return outboundEncodedPayload{}, fmt.Errorf(
			"sync provisional FI encoded payload: %w",
			err,
		)
	}
	info, err := encoded.Stat()
	if err != nil {
		return outboundEncodedPayload{}, fmt.Errorf(
			"stat provisional FI encoded payload: %w",
			err,
		)
	}
	if info.Size() <= 0 || uint64(info.Size()) != representation.EncodedDataBytes {
		return outboundEncodedPayload{}, errors.New(
			"provisional FI encoded payload size does not match encoded representation",
		)
	}
	if _, err := encoded.Seek(0, io.SeekStart); err != nil {
		return outboundEncodedPayload{}, fmt.Errorf(
			"rewind provisional FI encoded payload: %w",
			err,
		)
	}

	encodedOpen = false
	keepEncoded = true
	return outboundEncodedPayload{
		file:           encoded,
		path:           encodedPath,
		representation: representation,
	}, nil
}

func descriptorV2FromCanonical(
	canonical transportbatch.Descriptor,
	representation transportbatch.EncodedRepresentation,
) (transportbatch.Descriptor, error) {
	if canonical.Version != transportbatch.DescriptorVersion {
		return transportbatch.Descriptor{}, fmt.Errorf(
			"canonical FI outbound descriptor version must be %q, got %q",
			transportbatch.DescriptorVersion,
			canonical.Version,
		)
	}
	if err := canonical.Validate(); err != nil {
		return transportbatch.Descriptor{}, fmt.Errorf(
			"validate canonical FI outbound descriptor: %w",
			err,
		)
	}
	if err := representation.Validate(); err != nil {
		return transportbatch.Descriptor{}, fmt.Errorf(
			"validate FI outbound encoded representation: %w",
			err,
		)
	}

	value := canonical
	value.Version = transportbatch.DescriptorVersionV2
	value.DataEncoding = representation.DataEncoding
	value.EncodedDataBytes = representation.EncodedDataBytes
	value.EncodedDataSHA256 = representation.EncodedDataSHA256
	if err := value.Validate(); err != nil {
		return transportbatch.Descriptor{}, fmt.Errorf(
			"validate FI outbound descriptor 0.2: %w",
			err,
		)
	}
	return value, nil
}

func ensureOutboundEncodedEOF(file *os.File) error {
	extra, err := io.CopyN(io.Discard, file, 1)
	if extra != 0 {
		return errors.New("FI outbound encoded payload exceeds signed encoded byte count")
	}
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("FI outbound encoded payload did not terminate at signed byte count")
		}
		return fmt.Errorf("check FI outbound encoded payload end: %w", err)
	}
	return nil
}

func prepareNewOutboundFrameV2(
	config OutboundFrameConfig,
	canonical transportbatch.Descriptor,
	finalPath string,
) (OutboundFrame, error) {
	manifest, err := os.ReadFile(config.ManifestPath)
	if err != nil {
		return OutboundFrame{}, fmt.Errorf(
			"read published FI manifest for outbound frame: %w",
			err,
		)
	}
	manifestDigest := sha256.Sum256(manifest)
	if hex.EncodeToString(manifestDigest[:]) != canonical.ManifestSHA256 {
		return OutboundFrame{}, errors.New(
			"published FI manifest changed after descriptor construction",
		)
	}

	encoded, err := createOutboundEncodedPayload(config, canonical)
	if err != nil {
		return OutboundFrame{}, err
	}
	defer func() {
		_ = encoded.file.Close()
		_ = os.Remove(encoded.path)
	}()

	descriptor, err := descriptorV2FromCanonical(canonical, encoded.representation)
	if err != nil {
		return OutboundFrame{}, err
	}
	signedBatch, err := transportpackage.NewSignedBatch(
		descriptor,
		config.BatchSigningCertificate,
		config.BatchSigner,
	)
	if err != nil {
		return OutboundFrame{}, fmt.Errorf("sign FI outbound batch 0.2: %w", err)
	}

	provisional, err := os.CreateTemp(config.StageDir, ".fi-outbound-*.open")
	if err != nil {
		return OutboundFrame{}, fmt.Errorf("create provisional FI outbound frame: %w", err)
	}
	provisionalPath := provisional.Name()
	provisionalOpen := true
	keepProvisional := true
	defer func() {
		if provisionalOpen {
			_ = provisional.Close()
		}
		if keepProvisional {
			_ = os.Remove(provisionalPath)
		}
	}()

	if err := transportwire.WriteHeaderV2(provisional, signedBatch, manifest); err != nil {
		return OutboundFrame{}, fmt.Errorf("write FI outbound frame 0.2 header: %w", err)
	}
	if err := writeOutboundFull(provisional, manifest); err != nil {
		return OutboundFrame{}, fmt.Errorf("write FI outbound manifest payload: %w", err)
	}

	encodedHasher := sha256.New()
	written, err := io.CopyN(
		io.MultiWriter(provisional, encodedHasher),
		encoded.file,
		int64(descriptor.EncodedDataBytes),
	)
	if err != nil {
		return OutboundFrame{}, fmt.Errorf("write FI outbound encoded payload: %w", err)
	}
	if uint64(written) != descriptor.EncodedDataBytes {
		return OutboundFrame{}, fmt.Errorf(
			"write FI outbound encoded payload: wrote %d bytes, want %d",
			written,
			descriptor.EncodedDataBytes,
		)
	}
	if err := ensureOutboundEncodedEOF(encoded.file); err != nil {
		return OutboundFrame{}, err
	}
	if hex.EncodeToString(encodedHasher.Sum(nil)) != descriptor.EncodedDataSHA256 {
		return OutboundFrame{}, errors.New(
			"FI outbound encoded payload changed while frame was being staged",
		)
	}

	if err := provisional.Chmod(0o400); err != nil {
		return OutboundFrame{}, fmt.Errorf("make provisional FI outbound frame read-only: %w", err)
	}
	if err := provisional.Sync(); err != nil {
		return OutboundFrame{}, fmt.Errorf("sync provisional FI outbound frame: %w", err)
	}
	if err := provisional.Close(); err != nil {
		provisionalOpen = false
		return OutboundFrame{}, fmt.Errorf("close provisional FI outbound frame: %w", err)
	}
	provisionalOpen = false

	provisionalSent, err := validateStagedOutboundFrame(provisionalPath, descriptor)
	if err != nil {
		return OutboundFrame{}, fmt.Errorf(
			"validate provisional FI outbound frame 0.2: %w",
			err,
		)
	}

	published, err := publishOutboundFrame(provisionalPath, finalPath)
	if err != nil {
		return OutboundFrame{}, fmt.Errorf("publish FI outbound frame: %w", err)
	}
	if published {
		keepProvisional = false
		return OutboundFrame{
			Disposition: OutboundFrameDispositionNew,
			FramePath:   finalPath,
			Sent:        provisionalSent,
		}, nil
	}

	// A concurrent preparer may have produced a different valid RSA-PSS
	// signature, and its exact 0.2 frame is authoritative once it wins the
	// no-replace publication race. Validate it against the canonical Phase 1
	// facts rather than requiring this loser's encoded descriptor.
	existingSent, err := validateConcurrentlyPublishedOutboundFrame(
		finalPath,
		canonical,
	)
	if err != nil {
		return OutboundFrame{}, fmt.Errorf(
			"validate concurrently published FI outbound frame: %w",
			err,
		)
	}
	if err := os.Remove(provisionalPath); err != nil {
		return OutboundFrame{}, fmt.Errorf(
			"remove superseded provisional FI outbound frame: %w",
			err,
		)
	}
	keepProvisional = false

	return OutboundFrame{
		Disposition: OutboundFrameDispositionExisting,
		FramePath:   finalPath,
		Sent:        existingSent,
	}, nil
}

func readStagedOutboundFrameMagic(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open staged FI outbound frame magic: %w", err)
	}
	defer file.Close()

	var magic [8]byte
	if _, err := io.ReadFull(file, magic[:]); err != nil {
		return "", fmt.Errorf("read staged FI outbound frame magic: %w", err)
	}
	return string(magic[:]), nil
}

func stagedDescriptorMatchesExpected(
	actual transportbatch.Descriptor,
	expected transportbatch.Descriptor,
) error {
	if err := expected.Validate(); err != nil {
		return fmt.Errorf("validate expected FI outbound descriptor: %w", err)
	}

	switch expected.Version {
	case transportbatch.DescriptorVersion:
		switch actual.Version {
		case transportbatch.DescriptorVersion:
			if actual != expected {
				return errors.New(
					"staged FI outbound descriptor does not match published batch",
				)
			}
			return nil

		case transportbatch.DescriptorVersionV2:
			if actual.SourceID != expected.SourceID ||
				actual.BatchID != expected.BatchID ||
				actual.RecordCount != expected.RecordCount ||
				actual.DataBytes != expected.DataBytes ||
				actual.DataSHA256 != expected.DataSHA256 ||
				actual.ManifestSHA256 != expected.ManifestSHA256 {
				return errors.New(
					"staged FI outbound 0.2 descriptor does not match canonical published batch",
				)
			}
			return nil

		default:
			return fmt.Errorf(
				"staged FI outbound descriptor version %q is unsupported",
				actual.Version,
			)
		}

	case transportbatch.DescriptorVersionV2:
		if actual != expected {
			return errors.New(
				"staged FI outbound 0.2 descriptor does not match prepared frame",
			)
		}
		return nil

	default:
		return fmt.Errorf(
			"expected FI outbound descriptor version %q is unsupported",
			expected.Version,
		)
	}
}

func validateStagedOutboundFrame(
	path string,
	expected transportbatch.Descriptor,
) (SentFrame, error) {
	magic, err := readStagedOutboundFrameMagic(path)
	if err != nil {
		return SentFrame{}, err
	}

	switch magic {
	case outboundFrameMagicV1:
		return validateStagedOutboundFrameV1(path, expected)
	case outboundFrameMagicV2:
		return validateStagedOutboundFrameV2(path, expected)
	default:
		return SentFrame{}, errors.New("staged FI outbound frame magic is invalid")
	}
}

func validateStagedOutboundFrameV2(
	path string,
	expected transportbatch.Descriptor,
) (SentFrame, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return SentFrame{}, err
	}
	if !pathInfo.Mode().IsRegular() {
		return SentFrame{}, errors.New("staged FI outbound frame must be a regular file")
	}
	if pathInfo.Mode().Perm()&0o222 != 0 {
		return SentFrame{}, errors.New("staged FI outbound frame must be read-only")
	}
	if pathInfo.Size() <= 0 {
		return SentFrame{}, errors.New("staged FI outbound frame is empty")
	}

	file, err := os.Open(path)
	if err != nil {
		return SentFrame{}, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return SentFrame{}, err
	}
	if !os.SameFile(pathInfo, openedInfo) {
		return SentFrame{}, errors.New("staged FI outbound frame changed while being opened")
	}

	frameHasher := sha256.New()
	counter := &outboundCountWriter{}
	reader := io.TeeReader(file, io.MultiWriter(frameHasher, counter))
	header, err := transportwire.ReadHeaderV2(reader)
	if err != nil {
		return SentFrame{}, fmt.Errorf("read staged FI outbound frame 0.2 header: %w", err)
	}
	actual := header.SignedBatch.Descriptor
	if err := stagedDescriptorMatchesExpected(actual, expected); err != nil {
		return SentFrame{}, err
	}
	if err := verifyStagedOutboundSignature(header.SignedBatch); err != nil {
		return SentFrame{}, err
	}

	manifest := make([]byte, int(header.ManifestBytes))
	if _, err := io.ReadFull(reader, manifest); err != nil {
		return SentFrame{}, fmt.Errorf("read staged FI outbound manifest: %w", err)
	}
	manifestDigest := sha256.Sum256(manifest)
	if hex.EncodeToString(manifestDigest[:]) != actual.ManifestSHA256 {
		return SentFrame{}, errors.New("staged FI outbound manifest SHA-256 mismatch")
	}

	if actual.DataBytes > maxOutboundCopyDataBytes {
		return SentFrame{}, errors.New(
			"staged FI outbound canonical data byte count exceeds supported range",
		)
	}
	if actual.EncodedDataBytes > maxOutboundCopyDataBytes {
		return SentFrame{}, errors.New(
			"staged FI outbound encoded data byte count exceeds supported range",
		)
	}

	limited := &io.LimitedReader{
		R: reader,
		N: int64(actual.EncodedDataBytes),
	}
	encodedHasher := sha256.New()
	decoder, err := transportencoding.NewZstdDecoder(
		io.TeeReader(limited, encodedHasher),
	)
	if err != nil {
		return SentFrame{}, fmt.Errorf("create staged FI outbound zstd decoder: %w", err)
	}

	canonicalHasher := sha256.New()
	decoded, decodeErr := io.CopyN(
		canonicalHasher,
		decoder,
		int64(actual.DataBytes),
	)
	if decodeErr != nil {
		decoder.Close()
		return SentFrame{}, fmt.Errorf("decode staged FI outbound data: %w", decodeErr)
	}
	if uint64(decoded) != actual.DataBytes {
		decoder.Close()
		return SentFrame{}, errors.New("staged FI outbound decoded byte count mismatch")
	}

	extraDecoded, endErr := io.CopyN(io.Discard, decoder, 1)
	decoder.Close()
	if extraDecoded != 0 {
		return SentFrame{}, errors.New(
			"staged FI outbound decoded data exceeds signed canonical byte count",
		)
	}
	if !errors.Is(endErr, io.EOF) {
		if endErr == nil {
			return SentFrame{}, errors.New(
				"staged FI outbound decoded data did not terminate at signed boundary",
			)
		}
		return SentFrame{}, fmt.Errorf("check staged FI outbound decoded data end: %w", endErr)
	}
	if limited.N != 0 {
		return SentFrame{}, errors.New(
			"staged FI outbound zstd decoder did not consume the signed encoded payload",
		)
	}
	if hex.EncodeToString(encodedHasher.Sum(nil)) != actual.EncodedDataSHA256 {
		return SentFrame{}, errors.New("staged FI outbound encoded data SHA-256 mismatch")
	}
	if hex.EncodeToString(canonicalHasher.Sum(nil)) != actual.DataSHA256 {
		return SentFrame{}, errors.New("staged FI outbound canonical data SHA-256 mismatch")
	}

	var trailing [1]byte
	n, err := reader.Read(trailing[:])
	if n != 0 {
		return SentFrame{}, errors.New("staged FI outbound frame contains trailing bytes")
	}
	if !errors.Is(err, io.EOF) {
		if err == nil {
			return SentFrame{}, errors.New(
				"staged FI outbound frame did not terminate at expected boundary",
			)
		}
		return SentFrame{}, fmt.Errorf("check staged FI outbound frame end: %w", err)
	}

	afterOpen, err := file.Stat()
	if err != nil {
		return SentFrame{}, err
	}
	if !os.SameFile(openedInfo, afterOpen) || afterOpen.Size() != pathInfo.Size() {
		return SentFrame{}, errors.New("staged FI outbound frame changed during validation")
	}
	afterPath, err := os.Lstat(path)
	if err != nil {
		return SentFrame{}, err
	}
	if !os.SameFile(afterOpen, afterPath) || afterPath.Mode().Perm()&0o222 != 0 {
		return SentFrame{}, errors.New("staged FI outbound frame path changed during validation")
	}
	if counter.bytes != uint64(pathInfo.Size()) {
		return SentFrame{}, errors.New("staged FI outbound frame size changed during validation")
	}

	return SentFrame{
		Descriptor:  actual,
		FrameBytes:  counter.bytes,
		FrameSHA256: hex.EncodeToString(frameHasher.Sum(nil)),
	}, nil
}
