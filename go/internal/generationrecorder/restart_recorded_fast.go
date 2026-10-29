// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package generationrecorder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

// VerifyPreviouslyRecordedCustody is the restart fast path for a generation
// whose immutable semantic recorder receipt was already durably published.
//
// Missing receipt: return found=false, leaving the caller to execute the full
// trust/canonical/collector-semantic recorder path. A present but malformed,
// conflicting, or mismatched receipt fails closed; it is never replaced.
//
// The prior recorded receipt is proof of completed semantic validation only
// when it is bound to the exact stored FIGT transfer. That binding is checked
// by streaming a SHA-256 over every stored compressed transfer byte, validating
// the encoded payload digest and current batch-signing authorization. No
// decompression, JSONL processing or manifest replay occurs here.
func VerifyPreviouslyRecordedCustody(
	ctx context.Context,
	discovered transportgeneration.DiscoveredCustody,
	custodyConfig transportgeneration.CustodyConfig,
	recorderConfig DurableConfig,
) (DurableResult, bool, error) {
	if ctx == nil {
		return DurableResult{}, false, errors.New("FI recorded custody recovery requires context")
	}
	if err := ctx.Err(); err != nil {
		return DurableResult{}, false, err
	}
	if err := validateDurableConfig(recorderConfig); err != nil {
		return DurableResult{}, false, err
	}
	descriptor, err := transportgeneration.ReadDiscoveredCustodyDescriptor(
		discovered, custodyConfig.RootDir,
	)
	if err != nil {
		return DurableResult{}, false, fmt.Errorf("read recorded FI custody identity: %w", err)
	}

	root := recorderConfig.RootDir
	if recorderConfig.SourceNamespaces {
		root, err = recordedSourcePublicationDirectory(root, descriptor.SourceID)
		if err != nil {
			return DurableResult{}, false, err
		}
	}
	receiptPath := filepath.Join(root, RecordedReceiptObjectName(
		descriptor.SourceID, descriptor.GenerationID,
	))
	receiptInfo, err := os.Lstat(receiptPath)
	if errors.Is(err, os.ErrNotExist) {
		return DurableResult{}, false, nil
	}
	if err != nil {
		return DurableResult{}, false, err
	}
	if !receiptInfo.Mode().IsRegular() ||
		receiptInfo.Mode().Perm() != 0o400 ||
		receiptInfo.Size() <= 0 ||
		receiptInfo.Size() > maxRecordedReceiptBytes {
		return DurableResult{}, false, errors.New("existing FI generation recorded receipt is not a bounded read-only regular file")
	}

	file, err := os.Open(receiptPath)
	if err != nil {
		return DurableResult{}, false, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return DurableResult{}, false, err
	}
	if !os.SameFile(receiptInfo, opened) {
		_ = file.Close()
		return DurableResult{}, false, errors.New("FI generation recorded receipt changed while opening")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maxRecordedReceiptBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return DurableResult{}, false, readErr
	}
	if closeErr != nil {
		return DurableResult{}, false, closeErr
	}
	if int64(len(raw)) != receiptInfo.Size() {
		return DurableResult{}, false, errors.New("FI generation recorded receipt size changed during read")
	}
	after, err := os.Lstat(receiptPath)
	if err != nil {
		return DurableResult{}, false, err
	}
	if !os.SameFile(receiptInfo, after) ||
		after.Mode().Perm() != 0o400 ||
		after.Size() != receiptInfo.Size() {
		return DurableResult{}, false, errors.New("FI generation recorded receipt changed during read")
	}

	receipt, err := UnmarshalRecordedReceipt(raw)
	if err != nil {
		return DurableResult{}, false, fmt.Errorf("decode existing FI generation recorded receipt: %w", err)
	}
	canonical, err := MarshalRecordedReceipt(receipt)
	if err != nil {
		return DurableResult{}, false, err
	}
	if !bytes.Equal(raw, canonical) {
		return DurableResult{}, false, errors.New("existing FI generation recorded receipt has noncanonical bytes")
	}
	if receipt.Descriptor != descriptor {
		return DurableResult{}, false, errors.New("recorded FI generation descriptor conflicts with custody identity")
	}

	transfer, err := transportgeneration.VerifyDiscoveredCustodyOuter(
		ctx, discovered, custodyConfig,
	)
	if err != nil {
		return DurableResult{}, false, fmt.Errorf("verify existing FI generation outer transfer: %w", err)
	}
	if receipt.Descriptor != transfer.Descriptor ||
		receipt.MetadataBytes != transfer.MetadataBytes ||
		receipt.MetadataSHA256 != transfer.MetadataSHA256 ||
		receipt.TransferBytes != transfer.TransferBytes ||
		receipt.TransferSHA256 != transfer.TransferSHA256 {
		return DurableResult{}, false, errors.New("existing FI generation receipt does not match exact recorded transfer")
	}

	digest := sha256.Sum256(raw)
	return DurableResult{
		Disposition: RecordedDispositionAlreadyRecorded,
		Receipt: receipt,
		ReceiptBytes: uint64(len(raw)),
		ReceiptPath: receiptPath,
		ReceiptSHA256: hex.EncodeToString(digest[:]),
		Semantic: Result{
			ArtifactCount: receipt.Descriptor.ArtifactCount,
			BatchCount: receipt.BatchCount,
			DataBytes: receipt.DataBytes,
			GenerationID: receipt.Descriptor.GenerationID,
			RecordCount: receipt.RecordCount,
			SourceBytes: receipt.Descriptor.SourceBytes,
			SourceID: receipt.Descriptor.SourceID,
		},
	}, true, nil
}
