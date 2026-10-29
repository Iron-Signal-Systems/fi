// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportgeneration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Iron-Signal-Systems/fi/go/internal/transporttrust"
)

// VerifyDiscoveredCustodyOuter verifies a previously recorded, immutable FIGT
// object without decompressing its payload or interpreting any collector record.
//
// Callers MUST first establish that the exact source/generation identity has an
// existing, immutable, valid recorder receipt. This outer-only check cannot
// authorize a NEW recorder receipt: it relies on the full semantic validation
// proved when the existing receipt was originally published.
//
// Every byte of the stored FIGT transfer is hashed; the encoded payload SHA-256,
// wire metadata SHA-256, signed descriptor, source enrollment, and current
// signing trust are checked independently. The caller must compare the returned
// exact transfer identity against the existing recorder receipt.
func VerifyDiscoveredCustodyOuter(
	ctx context.Context,
	discovered DiscoveredCustody,
	config CustodyConfig,
) (TransferResult, error) {
	if ctx == nil {
		return TransferResult{}, errors.New("FI recorded custody verification context is required")
	}
	if err := ctx.Err(); err != nil {
		return TransferResult{}, err
	}
	if err := validateGenerationCustodyConfig(config); err != nil {
		return TransferResult{}, err
	}
	if err := validateDiscoveredCustody(discovered, config.RootDir); err != nil {
		return TransferResult{}, err
	}

	before, err := os.Lstat(discovered.Path)
	if err != nil {
		return TransferResult{}, fmt.Errorf("inspect recorded FI custody: %w", err)
	}
	if err := validateGenerationCustodyFileInfo(before, discovered.Bytes); err != nil {
		return TransferResult{}, err
	}

	file, err := os.Open(discovered.Path)
	if err != nil {
		return TransferResult{}, fmt.Errorf("open recorded FI custody: %w", err)
	}
	defer file.Close()

	opened, err := file.Stat()
	if err != nil {
		return TransferResult{}, err
	}
	if !os.SameFile(before, opened) {
		return TransferResult{}, errors.New("recorded FI custody changed during open")
	}

	offer, err := readDiscoveredCustodyOffer(file, discovered)
	if err != nil {
		return TransferResult{}, err
	}
	descriptor := offer.Descriptor
	if descriptor.SourceID != config.Receive.Source.SourceID {
		return TransferResult{}, errors.New("recorded FI custody source is not enrolled source")
	}
	if descriptor.ArtifactCount > maxReceiveArtifactCount ||
		descriptor.CanonicalBytes > config.Receive.MaxCanonicalBytes ||
		descriptor.EncodedDataBytes > config.Receive.MaxEncodedBytes {
		return TransferResult{}, errors.New("recorded FI custody exceeds configured receive limits")
	}
	expectedName := generationCustodyObjectName(descriptor.SourceID, descriptor.GenerationID)
	// The deterministic name binds the file to its source and generation identity.
	if filepath.Base(discovered.Path) != expectedName {
		return TransferResult{}, errors.New("recorded FI custody filename does not match signed identity")
	}

	if _, err := file.Seek(transferHeaderBytes, io.SeekStart); err != nil {
		return TransferResult{}, err
	}
	metadata := make([]byte, int(offer.MetadataBytes))
	if _, err := io.ReadFull(file, metadata); err != nil {
		return TransferResult{}, err
	}
	metadataDigest := sha256.Sum256(metadata)
	if hex.EncodeToString(metadataDigest[:]) != offer.MetadataSHA256 {
		return TransferResult{}, errors.New("recorded FI custody metadata digest differs from signed offer")
	}
	signed, err := UnmarshalSignedGeneration(metadata)
	if err != nil {
		return TransferResult{}, err
	}
	if signed.Descriptor != descriptor {
		return TransferResult{}, errors.New("recorded FI custody signed descriptor changed")
	}
	certificate, err := signed.BatchSigningCertificate()
	if err != nil {
		return TransferResult{}, err
	}
	authorized, err := transporttrust.VerifyBatchSigningCertificate(
		certificate,
		config.Receive.Root,
		config.Receive.BatchIssuer,
		config.Receive.BatchCRL,
		config.Receive.Source,
		config.Receive.CurrentTime,
	)
	if err != nil {
		return TransferResult{}, fmt.Errorf("authorize recorded FI custody signing certificate: %w", err)
	}
	if authorized != transporttrust.AuthorizationAuthorized {
		return TransferResult{}, fmt.Errorf("recorded FI custody signing authorization rejected: %s", authorized)
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return TransferResult{}, err
	}
	reader := &outerCustodyContextReader{ctx: ctx, reader: file}
	transferHasher := sha256.New()
	encodedHasher := sha256.New()
	prefixBytes := int64(transferHeaderBytes) + int64(offer.MetadataBytes)
	if _, err := io.CopyN(transferHasher, reader, prefixBytes); err != nil {
		return TransferResult{}, fmt.Errorf("hash recorded FI transfer envelope: %w", err)
	}
	if _, err := io.CopyN(
		io.MultiWriter(transferHasher, encodedHasher),
		reader,
		int64(descriptor.EncodedDataBytes),
	); err != nil {
		return TransferResult{}, fmt.Errorf("hash recorded FI encoded payload: %w", err)
	}
	var extra [1]byte
	if count, readErr := reader.Read(extra[:]); count != 0 || !errors.Is(readErr, io.EOF) {
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return TransferResult{}, readErr
		}
		return TransferResult{}, errors.New("recorded FI custody contains trailing transfer bytes")
	}
	encodedSHA := hex.EncodeToString(encodedHasher.Sum(nil))
	if encodedSHA != descriptor.EncodedDataSHA256 {
		return TransferResult{}, errors.New("recorded FI custody encoded SHA-256 mismatch")
	}
	after, err := os.Lstat(discovered.Path)
	if err != nil {
		return TransferResult{}, err
	}
	if !os.SameFile(before, after) {
		return TransferResult{}, errors.New("recorded FI custody changed during outer verification")
	}
	if err := validateGenerationCustodyFileInfo(after, discovered.Bytes); err != nil {
		return TransferResult{}, err
	}
	return TransferResult{
		Descriptor: descriptor,
		MetadataBytes: offer.MetadataBytes,
		MetadataSHA256: offer.MetadataSHA256,
		PayloadBytes: descriptor.EncodedDataBytes,
		PayloadSHA256: encodedSHA,
		TransferBytes: discovered.Bytes,
		TransferSHA256: hex.EncodeToString(transferHasher.Sum(nil)),
	}, nil
}

// outerCustodyContextReader makes the byte-stream hash cancellable even when
// the receiver has not yet entered its network listener.
type outerCustodyContextReader struct {
	ctx context.Context
	reader io.Reader
}

func (r *outerCustodyContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}
