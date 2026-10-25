// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

const rawUSNSourceRetiredPrefix = ".fi-usn-raw-retired-"

// tombstoneVerifiedRawUSNSource performs ONLY the durable namespace transition
// for a previously verified USN source. The receipt must already have been
// written by the committed-generation preflight. This function neither
// publishes the sealed generation nor deletes any raw source bytes.
//
// It is not yet called from the sender: recovery of this new namespace must be
// integrated and tested before enabling the transition in production.
func tombstoneVerifiedRawUSNSource(
	ctx context.Context,
	raw RawGeneration,
	sealedDir string,
	expected GenerationSourceCustodyReceipt,
) (string, error) {
	if ctx == nil {
		return "", errors.New("FI raw source tombstone context is required")
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if err := validateSourceCustodyReceipt(expected); err != nil {
		return "", err
	}
	if expected.GenerationID != raw.GenerationID {
		return "", fmt.Errorf(
			"%w: source and receipt generation identities differ",
			ErrGenerationSourceCustodyConflict,
		)
	}

	rawRoot := filepath.Dir(raw.GenerationDir)
	if err := validateRawGenerationRoot(rawRoot); err != nil {
		return "", err
	}
	if err := validateRawGeneration(raw, rawRoot); err != nil {
		return "", err
	}
	initial, err := os.Lstat(raw.GenerationDir)
	if err != nil {
		return "", err
	}

	// Only captured USN sources belong in this retirement namespace.
	// Malformed or unverifiable source manifests fail closed.
	if err := guardRawGenerationRetirement(raw.GenerationDir); !errors.Is(err, ErrSourceCustodyHandoffRequired) {
		if err == nil {
			return "", fmt.Errorf(
				"%w: generation does not contain a captured USN source",
				ErrGenerationSourceCustodyConflict,
			)
		}
		return "", err
	}

	receiptPath, err := generationSourceCustodyPath(
		sealedDir, raw.GenerationID,
	)
	if err != nil {
		return "", err
	}

	stored, found, err := readSourceCustodyReceipt(receiptPath)
	if err != nil {
		return "", err
	}
	if !found || !reflect.DeepEqual(stored, expected) {
		return "", fmt.Errorf(
			"%w: exact durable custody receipt is absent or different",
			ErrGenerationSourceCustodyConflict,
		)
	}

	// Independently reload the signed replacement. A receipt that names
	// different signed content cannot authorize a namespace transition.
	sealed, err := transportgeneration.LoadSealedGeneration(sealedDir)
	if err != nil {
		return "", fmt.Errorf(
			"reload FI sealed custody replacement: %w", err,
		)
	}
	descriptor := sealed.Signed.Descriptor
	if descriptor.GenerationID != raw.GenerationID ||
		descriptor.SourceID != expected.SourceID ||
		descriptor.CanonicalSHA256 != expected.CanonicalSHA256 ||
		descriptor.EncodedDataSHA256 != expected.EncodedSHA256 {
		return "", fmt.Errorf(
			"%w: sealed replacement identity differs from the receipt",
			ErrGenerationSourceCustodyConflict,
		)
	}

	metadata, err := readGenerationRetirementMetadata(sealed.MetadataPath)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(metadata)
	if hex.EncodeToString(digest[:]) != expected.SignedMetadataSHA256 {
		return "", fmt.Errorf(
			"%w: signed metadata digest differs from the receipt",
			ErrGenerationSourceCustodyConflict,
		)
	}

	if err := transportgeneration.VerifyPublishedGenerationPayload(sealed); err != nil {
		return "", fmt.Errorf(
			"verify durable sealed replacement: %w", err,
		)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	// Recheck durable custody before the rename. The caller must maintain
	// exclusive ownership of the frozen source during this operation.
	current, found, err := readSourceCustodyReceipt(receiptPath)
	if err != nil {
		return "", err
	}
	if !found || !reflect.DeepEqual(current, expected) {
		return "", fmt.Errorf(
			"%w: custody receipt changed before raw retirement",
			ErrGenerationSourceCustodyConflict,
		)
	}

	beforeRename, err := os.Lstat(raw.GenerationDir)
	if err != nil || !os.SameFile(initial, beforeRename) {
		return "", fmt.Errorf(
			"%w: frozen source changed before rename: %v",
			ErrGenerationSourceCustodyConflict, err,
		)
	}

	tombstone := filepath.Join(
		rawRoot,
		rawUSNSourceRetiredPrefix+raw.GenerationID,
	)

	if _, err := os.Lstat(tombstone); err == nil {
		return "", fmt.Errorf(
			"%w: raw source tombstone already exists",
			ErrGenerationSourceCustodyConflict,
		)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	// Perform a same-volume durable namespace rename. Never delete the
	// source here. If interrupted, all raw bytes remain in the tombstone.
	if err := publishGenerationDirectory(
		raw.GenerationDir, tombstone,
	); err != nil {
		return "", fmt.Errorf(
			"publish FI raw source tombstone: %w", err,
		)
	}

	afterRename, err := os.Lstat(tombstone)
	if err != nil ||
		!afterRename.IsDir() ||
		!os.SameFile(initial, afterRename) {
		return "", fmt.Errorf(
			"%w: retired raw source directory identity changed: %v",
			ErrGenerationSourceCustodyConflict, err,
		)
	}

	return tombstone, nil
}
