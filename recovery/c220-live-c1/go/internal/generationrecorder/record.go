// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package generationrecorder

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

const (
	RecordedReceiptVersion = "fi-generation-recorded/0.1"

	maxRecordedReceiptBytes = 256 << 10

	maxRecordedTransportMetadataBytes = 512 << 10

	generationTransferHeaderBytes = 20
)

// RecordedReceipt is the immutable recorder-side statement that one exact
// transport generation passed the complete collector batch semantic gate.
//
// The receipt is intentionally small. The exact FIGT transfer remains in
// durable transport custody; the receipt binds that custody identity to the
// semantic facts proved by generationrecorder.
//
// This receipt is not a database materialization and does not by itself send an
// acknowledgement or retire the sender object.
type RecordedReceipt struct {
	Version string `json:"version"`

	Descriptor transportgeneration.Descriptor `json:"descriptor"`

	MetadataBytes  uint64 `json:"metadata_bytes"`
	MetadataSHA256 string `json:"metadata_sha256"`

	TransferBytes  uint64 `json:"transfer_bytes"`
	TransferSHA256 string `json:"transfer_sha256"`

	BatchCount  uint64 `json:"batch_count"`
	DataBytes   uint64 `json:"data_bytes"`
	RecordCount uint64 `json:"record_count"`
}

// MarshalRecordedReceipt returns the deterministic JSON representation stored
// at the durable recorder boundary.
func MarshalRecordedReceipt(
	receipt RecordedReceipt,
) (
	[]byte,
	error,
) {
	if err :=
		receipt.Validate(); err != nil {
		return nil, err
	}

	raw, err :=
		json.Marshal(
			receipt,
		)
	if err != nil {
		return nil, err
	}

	if len(raw)+1 >
		maxRecordedReceiptBytes {
		return nil,
			errors.New(
				"FI generation recorded receipt exceeds supported byte limit",
			)
	}

	raw =
		append(
			raw,
			'\n',
		)

	return raw, nil
}

// UnmarshalRecordedReceipt strictly decodes one durable recorder receipt.
func UnmarshalRecordedReceipt(
	raw []byte,
) (
	RecordedReceipt,
	error,
) {
	if len(raw) == 0 ||
		len(raw) >
			maxRecordedReceiptBytes {
		return RecordedReceipt{},
			errors.New(
				"FI generation recorded receipt byte count is outside bounds",
			)
	}

	decoder :=
		json.NewDecoder(
			bytes.NewReader(
				raw,
			),
		)

	decoder.DisallowUnknownFields()

	var receipt RecordedReceipt

	if err :=
		decoder.Decode(
			&receipt,
		); err != nil {
		return RecordedReceipt{}, err
	}

	var trailing any

	if err :=
		decoder.Decode(
			&trailing,
		); err != io.EOF {
		return RecordedReceipt{},
			errors.New(
				"FI generation recorded receipt contains trailing JSON",
			)
	}

	if err :=
		receipt.Validate(); err != nil {
		return RecordedReceipt{}, err
	}

	return receipt, nil
}

// Validate applies the stable recorder receipt contract.
func (
	receipt RecordedReceipt,
) Validate() error {
	if receipt.Version !=
		RecordedReceiptVersion {
		return errors.New(
			"invalid FI generation recorded receipt version",
		)
	}

	if err :=
		receipt.Descriptor.Validate(); err != nil {
		return fmt.Errorf(
			"invalid FI generation recorded receipt descriptor: %w",
			err,
		)
	}

	if receipt.MetadataBytes == 0 ||
		receipt.MetadataBytes >
			maxRecordedTransportMetadataBytes {
		return errors.New(
			"FI generation recorded receipt metadata byte count is outside wire bounds",
		)
	}

	if err :=
		validateRecorderSHA256(
			"metadata SHA-256",
			receipt.MetadataSHA256,
		); err != nil {
		return err
	}

	if err :=
		validateRecorderSHA256(
			"transfer SHA-256",
			receipt.TransferSHA256,
		); err != nil {
		return err
	}

	expectedTransferBytes :=
		uint64(
			generationTransferHeaderBytes,
		)

	if receipt.MetadataBytes >
		^uint64(0)-
			expectedTransferBytes {
		return errors.New(
			"FI generation recorded receipt transfer byte count overflow",
		)
	}

	expectedTransferBytes +=
		receipt.MetadataBytes

	if receipt.Descriptor.EncodedDataBytes >
		^uint64(0)-
			expectedTransferBytes {
		return errors.New(
			"FI generation recorded receipt transfer byte count overflow",
		)
	}

	expectedTransferBytes +=
		receipt.Descriptor.EncodedDataBytes

	if receipt.TransferBytes !=
		expectedTransferBytes {
		return errors.New(
			"FI generation recorded receipt transfer byte count is inconsistent",
		)
	}

	if receipt.BatchCount == 0 {
		return errors.New(
			"FI generation recorded receipt batch count must be greater than zero",
		)
	}

	if receipt.BatchCount >
		^uint64(0)/2 ||
		receipt.BatchCount*2 !=
			receipt.Descriptor.ArtifactCount {
		return errors.New(
			"FI generation recorded receipt batch count does not match descriptor artifact count",
		)
	}

	if receipt.DataBytes == 0 ||
		receipt.DataBytes >
			receipt.Descriptor.SourceBytes {
		return errors.New(
			"FI generation recorded receipt data byte count is outside source bounds",
		)
	}

	if receipt.RecordCount == 0 {
		return errors.New(
			"FI generation recorded receipt record count must be greater than zero",
		)
	}

	return nil
}

func recordedReceiptFromResult(
	transfer transportgeneration.TransferResult,
	semantic Result,
) (
	RecordedReceipt,
	error,
) {
	if err :=
		validateTransferResult(
			transfer,
		); err != nil {
		return RecordedReceipt{}, err
	}

	if semantic.SourceID !=
		transfer.Descriptor.SourceID ||
		semantic.GenerationID !=
			transfer.Descriptor.GenerationID ||
		semantic.ArtifactCount !=
			transfer.Descriptor.ArtifactCount ||
		semantic.SourceBytes !=
			transfer.Descriptor.SourceBytes {
		return RecordedReceipt{},
			errors.New(
				"FI generation recorder semantic result does not match validated transfer descriptor",
			)
	}

	receipt :=
		RecordedReceipt{
			Version: RecordedReceiptVersion,

			Descriptor: transfer.Descriptor,

			MetadataBytes: transfer.MetadataBytes,

			MetadataSHA256: transfer.MetadataSHA256,

			TransferBytes: transfer.TransferBytes,

			TransferSHA256: transfer.TransferSHA256,

			BatchCount: semantic.BatchCount,

			DataBytes: semantic.DataBytes,

			RecordCount: semantic.RecordCount,
		}

	if err :=
		receipt.Validate(); err != nil {
		return RecordedReceipt{}, err
	}

	return receipt, nil
}

func validateRecorderSHA256(
	name string,
	value string,
) error {
	if len(value) != 64 ||
		value !=
			strings.ToLower(
				value,
			) {
		return fmt.Errorf(
			"invalid FI generation recorder %s",
			name,
		)
	}

	decoded, err :=
		hex.DecodeString(
			value,
		)
	if err != nil ||
		len(decoded) != 32 {
		return fmt.Errorf(
			"invalid FI generation recorder %s",
			name,
		)
	}

	return nil
}

func validateTransferResult(
	result transportgeneration.TransferResult,
) error {
	if err :=
		result.Descriptor.Validate(); err != nil {
		return fmt.Errorf(
			"invalid FI generation recorder transfer descriptor: %w",
			err,
		)
	}

	if result.MetadataBytes == 0 ||
		result.MetadataBytes >
			maxRecordedTransportMetadataBytes {
		return errors.New(
			"FI generation recorder transfer metadata byte count is outside wire bounds",
		)
	}

	if err :=
		validateRecorderSHA256(
			"metadata SHA-256",
			result.MetadataSHA256,
		); err != nil {
		return err
	}

	if result.PayloadBytes !=
		result.Descriptor.EncodedDataBytes ||
		result.PayloadSHA256 !=
			result.Descriptor.EncodedDataSHA256 {
		return errors.New(
			"FI generation recorder transfer payload identity does not match descriptor",
		)
	}

	if err :=
		validateRecorderSHA256(
			"transfer SHA-256",
			result.TransferSHA256,
		); err != nil {
		return err
	}

	expectedTransferBytes :=
		uint64(
			generationTransferHeaderBytes,
		)

	if result.MetadataBytes >
		^uint64(0)-
			expectedTransferBytes {
		return errors.New(
			"FI generation recorder transfer byte count overflow",
		)
	}

	expectedTransferBytes +=
		result.MetadataBytes

	if result.PayloadBytes >
		^uint64(0)-
			expectedTransferBytes {
		return errors.New(
			"FI generation recorder transfer byte count overflow",
		)
	}

	expectedTransferBytes +=
		result.PayloadBytes

	if result.TransferBytes !=
		expectedTransferBytes {
		return errors.New(
			"FI generation recorder transfer byte count is inconsistent",
		)
	}

	return nil
}
