// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportgeneration

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ReadDurableCustodyArtifacts reopens one already-published generation custody
// object, revalidates the exact FIGT transfer and current enrolled signing
// trust, and exposes canonical artifacts to the supplied streaming handler.
//
// This is a recorder-side read adapter. It does not modify custody, publish a
// recorder receipt, send an acknowledgement, or retire the sender object.
func ReadDurableCustodyArtifacts(
	custody CustodyResult,
	config CustodyConfig,
	handler CanonicalArtifactHandler,
) (
	TransferResult,
	error,
) {
	if handler == nil {
		return TransferResult{}, errors.New(
			"FI generation durable custody artifact handler is required",
		)
	}

	if err := validateGenerationCustodyConfig(config); err != nil {
		return TransferResult{}, err
	}

	if err := validateGenerationCustodyResult(custody, config.RootDir); err != nil {
		return TransferResult{}, err
	}

	before, err := os.Lstat(custody.CustodyPath)
	if err != nil {
		return TransferResult{}, fmt.Errorf(
			"inspect FI generation durable custody object: %w",
			err,
		)
	}

	if err := validateGenerationCustodyFileInfo(before, custody.Transfer.TransferBytes); err != nil {
		return TransferResult{}, err
	}

	file, err := os.Open(custody.CustodyPath)
	if err != nil {
		return TransferResult{}, fmt.Errorf(
			"open FI generation durable custody object: %w",
			err,
		)
	}

	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return TransferResult{}, fmt.Errorf(
			"stat opened FI generation durable custody object: %w",
			err,
		)
	}

	if !os.SameFile(before, opened) {
		_ = file.Close()
		return TransferResult{}, errors.New(
			"FI generation durable custody object changed while being opened",
		)
	}

	offer := Offer{
		Version:        OfferVersion,
		Descriptor:     custody.Transfer.Descriptor,
		MetadataBytes:  custody.Transfer.MetadataBytes,
		MetadataSHA256: custody.Transfer.MetadataSHA256,
	}

	transfer, readErr := readValidatedTransfer(
		file,
		offer,
		config.Receive,
		handler,
	)

	var extra [1]byte
	extraCount, extraErr := file.Read(extra[:])

	closeErr := file.Close()

	if readErr != nil {
		return TransferResult{}, fmt.Errorf(
			"revalidate FI generation durable custody transfer: %w",
			readErr,
		)
	}

	if extraCount != 0 || !errors.Is(extraErr, io.EOF) {
		return TransferResult{}, errors.New(
			"FI generation durable custody object contains trailing transfer bytes",
		)
	}

	if closeErr != nil {
		return TransferResult{}, fmt.Errorf(
			"close FI generation durable custody object: %w",
			closeErr,
		)
	}

	if transfer != custody.Transfer {
		return TransferResult{}, errors.New(
			"FI generation durable custody transfer identity changed during recorder read",
		)
	}

	after, err := os.Lstat(custody.CustodyPath)
	if err != nil {
		return TransferResult{}, fmt.Errorf(
			"reinspect FI generation durable custody object: %w",
			err,
		)
	}

	if !os.SameFile(before, after) {
		return TransferResult{}, errors.New(
			"FI generation durable custody object changed during recorder read",
		)
	}

	if err := validateGenerationCustodyFileInfo(after, custody.Transfer.TransferBytes); err != nil {
		return TransferResult{}, err
	}

	return transfer, nil
}

func validateGenerationCustodyFileInfo(
	info os.FileInfo,
	expectedBytes uint64,
) error {
	if info == nil {
		return errors.New(
			"FI generation durable custody file information is required",
		)
	}

	if info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o400 {
		return errors.New(
			"FI generation durable custody object must be a read-only regular file",
		)
	}

	if info.Size() <= 0 || uint64(info.Size()) != expectedBytes {
		return errors.New(
			"FI generation durable custody object size does not match validated transfer",
		)
	}

	return nil
}

func validateGenerationCustodyResult(
	custody CustodyResult,
	root string,
) error {
	switch custody.Disposition {
	case CustodyDispositionDuplicate, CustodyDispositionExisting, CustodyDispositionNew:
	default:
		return errors.New(
			"FI generation durable custody disposition is invalid",
		)
	}

	if err := custody.Transfer.Descriptor.Validate(); err != nil {
		return fmt.Errorf(
			"validate FI generation durable custody descriptor: %w",
			err,
		)
	}

	offer := Offer{
		Version:        OfferVersion,
		Descriptor:     custody.Transfer.Descriptor,
		MetadataBytes:  custody.Transfer.MetadataBytes,
		MetadataSHA256: custody.Transfer.MetadataSHA256,
	}

	if err := offer.Validate(); err != nil {
		return fmt.Errorf(
			"validate FI generation durable custody metadata identity: %w",
			err,
		)
	}

	if custody.Transfer.PayloadBytes != custody.Transfer.Descriptor.EncodedDataBytes ||
		custody.Transfer.PayloadSHA256 != custody.Transfer.Descriptor.EncodedDataSHA256 {
		return errors.New(
			"FI generation durable custody payload identity does not match descriptor",
		)
	}

	if err := validateSHA256(
		"transfer SHA-256",
		custody.Transfer.TransferSHA256,
	); err != nil {
		return err
	}

	expectedTransferBytes := uint64(transferHeaderBytes)

	if custody.Transfer.MetadataBytes > ^uint64(0)-expectedTransferBytes {
		return errors.New(
			"FI generation durable custody transfer byte count overflow",
		)
	}

	expectedTransferBytes += custody.Transfer.MetadataBytes

	if custody.Transfer.PayloadBytes > ^uint64(0)-expectedTransferBytes {
		return errors.New(
			"FI generation durable custody transfer byte count overflow",
		)
	}

	expectedTransferBytes += custody.Transfer.PayloadBytes

	if custody.Transfer.TransferBytes != expectedTransferBytes ||
		custody.CustodyBytes != custody.Transfer.TransferBytes {
		return errors.New(
			"FI generation durable custody byte count is inconsistent",
		)
	}

	if err := validateSHA256(
		"custody SHA-256",
		custody.CustodySHA256,
	); err != nil {
		return err
	}

	if custody.CustodySHA256 != custody.Transfer.TransferSHA256 {
		return errors.New(
			"FI generation durable custody SHA-256 does not match validated transfer",
		)
	}

	expectedPath := filepath.Join(
		root,
		generationCustodyObjectName(
			custody.Transfer.Descriptor.SourceID,
			custody.Transfer.Descriptor.GenerationID,
		),
	)

	if filepath.Clean(custody.CustodyPath) != filepath.Clean(expectedPath) {
		return errors.New(
			"FI generation durable custody path does not match configured custody identity",
		)
	}

	return nil
}
