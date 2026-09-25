// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportreceiver

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationready"
	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

var (
	ErrGenerationNotEnabled    = errors.New("FI receiver generation transport is not enabled")
	ErrGenerationOfferRejected = errors.New("FI generation offer rejected")
)

// GenerationReceiveConfig binds the transport-custody and recorder boundaries
// used by one authenticated generation transaction.
//
// The caller is responsible for authenticating the transport connection before
// this transaction begins. The generation's Batch Signing identity is still
// independently validated from the signed metadata during custody intake and
// again when the recorder reopens durable custody.
type GenerationReceiveConfig struct {
	Custody   transportgeneration.CustodyConfig
	ReadyRoot string
	Recorder  generationrecorder.DurableConfig
}

// GenerationReceiveResult captures the complete receiver-side generation
// transaction state.
//
// Acknowledgement is populated only after the exact transfer has crossed
// durable custody and the complete generation has crossed the durable recorder
// boundary. An acknowledgement write failure may therefore return this result
// together with an error; the durable custody and recorder receipt remain
// authoritative and an exact retry can safely return already_recorded.
type GenerationReceiveResult struct {
	Offer           transportgeneration.Offer
	Decision        transportgeneration.Decision
	Custody         transportgeneration.CustodyResult
	Recorder        generationrecorder.DurableResult
	ReadyPath       string
	ReadyWarning    string
	Acknowledgement transportgeneration.Acknowledgement
}

// ReceiveGenerationAndAcknowledge performs one generation-specific receiver
// transaction after authenticated transport has been established.
//
// Sequence:
//
//  1. read and validate FIGO0001 offer;
//  2. apply source/capacity admission and write FIGD0001 decision;
//  3. receive and durably publish the exact FIGT0001 transfer;
//  4. reopen custody, revalidate current signing trust, and durably record all
//     collector batch semantics;
//  5. best-effort publish a non-authoritative ingest-ready hint after the
//     immutable recorder receipt is durable; and
//  6. only then write FIGA0001 recorded/already_recorded.
//
// No success acknowledgement is written for custody, trust, semantic, or
// recorder failure. Ingest-ready publication failure is returned as warning
// state and does not suppress FIGA because the immutable recorder receipt
// remains authoritative. This function never retires sender-side state.
func ReceiveGenerationAndAcknowledge(
	reader io.Reader,
	writer io.Writer,
	config GenerationReceiveConfig,
) (
	GenerationReceiveResult,
	error,
) {
	if reader == nil {
		return GenerationReceiveResult{}, errors.New(
			"FI generation transaction reader is required",
		)
	}

	if writer == nil {
		return GenerationReceiveResult{}, errors.New(
			"FI generation transaction writer is required",
		)
	}

	if err := validateGenerationReceiveConfig(config); err != nil {
		return GenerationReceiveResult{}, err
	}

	offer, err := transportgeneration.ReadOffer(reader)
	if err != nil {
		return GenerationReceiveResult{}, fmt.Errorf(
			"read FI generation offer: %w",
			err,
		)
	}

	result := GenerationReceiveResult{
		Offer: offer,
	}

	decision, rejectReason, err := generationAdmissionDecision(
		offer,
		config,
	)
	if err != nil {
		return result, err
	}

	result.Decision = decision

	if err := transportgeneration.WriteDecision(writer, decision); err != nil {
		return result, fmt.Errorf(
			"write FI generation decision: %w",
			err,
		)
	}

	if rejectReason != "" {
		return result, fmt.Errorf(
			"%w: %s",
			ErrGenerationOfferRejected,
			rejectReason,
		)
	}

	custody, err := transportgeneration.ReceiveToDurableCustody(
		reader,
		offer,
		config.Custody,
	)
	if err != nil {
		return result, fmt.Errorf(
			"receive FI generation to durable custody: %w",
			err,
		)
	}

	result.Custody = custody

	recorded, err := generationrecorder.RecordCustodyDurably(
		custody,
		config.Custody,
		config.Recorder,
	)
	if err != nil {
		return result, fmt.Errorf(
			"record FI generation from durable custody: %w",
			err,
		)
	}

	result.Recorder = recorded

	result.ReadyPath, result.ReadyWarning =
		publishGenerationReady(
			config.ReadyRoot,
			recorded,
		)

	acknowledgement, err := generationAcknowledgementFromRecorded(
		custody,
		recorded,
	)
	if err != nil {
		return result, fmt.Errorf(
			"construct FI generation recorded acknowledgement: %w",
			err,
		)
	}

	result.Acknowledgement = acknowledgement

	if err := transportgeneration.WriteAcknowledgement(
		writer,
		acknowledgement,
	); err != nil {
		return result, fmt.Errorf(
			"write FI generation recorded acknowledgement: %w",
			err,
		)
	}

	return result, nil
}

func generationAdmissionDecision(
	offer transportgeneration.Offer,
	config GenerationReceiveConfig,
) (
	transportgeneration.Decision,
	string,
	error,
) {
	if offer.Descriptor.SourceID != config.Custody.Receive.Source.SourceID {
		decision, err := transportgeneration.NewDecision(
			offer,
			false,
			"SOURCE_ID_MISMATCH",
		)
		return decision, "SOURCE_ID_MISMATCH", err
	}

	if offer.Descriptor.CanonicalBytes > config.Custody.Receive.MaxCanonicalBytes {
		decision, err := transportgeneration.NewDecision(
			offer,
			false,
			"CANONICAL_BYTES_EXCEED_LIMIT",
		)
		return decision, "CANONICAL_BYTES_EXCEED_LIMIT", err
	}

	if offer.Descriptor.EncodedDataBytes > config.Custody.Receive.MaxEncodedBytes {
		decision, err := transportgeneration.NewDecision(
			offer,
			false,
			"ENCODED_BYTES_EXCEED_LIMIT",
		)
		return decision, "ENCODED_BYTES_EXCEED_LIMIT", err
	}

	decision, err := transportgeneration.NewDecision(
		offer,
		true,
		"",
	)
	return decision, "", err
}

func generationAcknowledgementFromRecorded(
	custody transportgeneration.CustodyResult,
	recorded generationrecorder.DurableResult,
) (
	transportgeneration.Acknowledgement,
	error,
) {
	if recorded.Receipt.Descriptor != custody.Transfer.Descriptor ||
		recorded.Receipt.MetadataBytes != custody.Transfer.MetadataBytes ||
		recorded.Receipt.MetadataSHA256 != custody.Transfer.MetadataSHA256 ||
		recorded.Receipt.TransferBytes != custody.Transfer.TransferBytes ||
		recorded.Receipt.TransferSHA256 != custody.Transfer.TransferSHA256 {
		return transportgeneration.Acknowledgement{}, errors.New(
			"FI generation recorder receipt does not bind exact durable custody transfer identity",
		)
	}

	var outcome string

	switch recorded.Disposition {
	case generationrecorder.RecordedDispositionNew:
		outcome = transportgeneration.AcknowledgementOutcomeRecorded
	case generationrecorder.RecordedDispositionAlreadyRecorded:
		outcome = transportgeneration.AcknowledgementOutcomeAlreadyRecorded
	default:
		return transportgeneration.Acknowledgement{}, fmt.Errorf(
			"unsupported FI generation recorder disposition %q",
			recorded.Disposition,
		)
	}

	acknowledgement, err := transportgeneration.NewAcknowledgement(
		outcome,
		custody.Transfer,
	)
	if err != nil {
		return transportgeneration.Acknowledgement{}, err
	}

	if err := transportgeneration.AcknowledgementMatches(
		acknowledgement,
		custody.Transfer,
	); err != nil {
		return transportgeneration.Acknowledgement{}, err
	}

	return acknowledgement, nil
}

func publishGenerationReady(
	readyRoot string,
	recorded generationrecorder.DurableResult,
) (string, string) {
	ready, err := generationready.Publish(
		readyRoot,
		filepath.Base(recorded.ReceiptPath),
	)
	if err != nil {
		return "", err.Error()
	}

	return ready.Path, ""
}

func receiveAuthenticatedGeneration(
	reader io.Reader,
	writer io.Writer,
	config Config,
	currentTime time.Time,
) (
	GenerationReceiveResult,
	error,
) {
	if !generationListenerEnabled(config) {
		offer, err := transportgeneration.ReadOffer(reader)
		if err != nil {
			return GenerationReceiveResult{}, fmt.Errorf(
				"read disabled FI generation offer: %w",
				err,
			)
		}

		decision, err := transportgeneration.NewDecision(
			offer,
			false,
			"GENERATION_DISABLED",
		)
		if err != nil {
			return GenerationReceiveResult{Offer: offer}, err
		}

		result := GenerationReceiveResult{
			Offer:    offer,
			Decision: decision,
		}

		if err := transportgeneration.WriteDecision(
			writer,
			decision,
		); err != nil {
			return result, fmt.Errorf(
				"write disabled FI generation decision: %w",
				err,
			)
		}

		return result, ErrGenerationNotEnabled
	}

	return ReceiveGenerationAndAcknowledge(
		reader,
		writer,
		generationReceiveConfigFromListener(
			config,
			currentTime,
		),
	)
}

func generationListenerEnabled(
	config Config,
) bool {
	return config.GenerationEnabled
}

func generationReceiveConfigFromListener(
	config Config,
	currentTime time.Time,
) GenerationReceiveConfig {
	return GenerationReceiveConfig{
		Custody: transportgeneration.CustodyConfig{
			Receive: transportgeneration.ReceiveConfig{
				BatchCRL:          config.BatchCRL,
				BatchIssuer:       config.BatchIssuer,
				CurrentTime:       currentTime,
				MaxCanonicalBytes: config.GenerationMaxCanonicalBytes,
				MaxEncodedBytes:   config.GenerationMaxEncodedBytes,
				Root:              config.Root,
				Source:            config.Source,
			},
			RootDir: config.GenerationCustodyRoot,
		},
		ReadyRoot: config.GenerationReadyRoot,
		Recorder: generationrecorder.DurableConfig{
			RootDir: config.GenerationRecordedRoot,
			Semantic: generationrecorder.Config{
				MaxManifestBytes: config.GenerationMaxManifestBytes,
			},
		},
	}
}

func validateGenerationListenerConfig(
	config Config,
) error {
	configured :=
		config.GenerationCustodyRoot != "" ||
			config.GenerationReadyRoot != "" ||
			config.GenerationRecordedRoot != "" ||
			config.GenerationMaxCanonicalBytes != 0 ||
			config.GenerationMaxEncodedBytes != 0 ||
			config.GenerationMaxManifestBytes != 0

	if !generationListenerEnabled(config) {
		if configured {
			return errors.New(
				"FI generation listener settings require explicit enablement",
			)
		}

		return nil
	}

	if config.GenerationCustodyRoot == "" ||
		config.GenerationReadyRoot == "" ||
		config.GenerationRecordedRoot == "" ||
		config.GenerationMaxCanonicalBytes == 0 ||
		config.GenerationMaxEncodedBytes == 0 ||
		config.GenerationMaxManifestBytes == 0 {
		return errors.New(
			"FI generation listener settings must all be configured when enabled",
		)
	}

	if !filepath.IsAbs(config.GenerationCustodyRoot) ||
		!filepath.IsAbs(config.GenerationReadyRoot) ||
		!filepath.IsAbs(config.GenerationRecordedRoot) {
		return errors.New(
			"FI generation listener custody, recorder, and ready roots must be absolute",
		)
	}

	custodyRoot := filepath.Clean(config.GenerationCustodyRoot)
	readyRoot := filepath.Clean(config.GenerationReadyRoot)
	recordedRoot := filepath.Clean(config.GenerationRecordedRoot)

	if custodyRoot == recordedRoot ||
		custodyRoot == readyRoot ||
		recordedRoot == readyRoot {
		return errors.New(
			"FI generation custody, recorder, and ready roots must be distinct",
		)
	}

	if config.CustodyRoot != "" &&
		(custodyRoot == filepath.Clean(config.CustodyRoot) ||
			recordedRoot == filepath.Clean(config.CustodyRoot) ||
			readyRoot == filepath.Clean(config.CustodyRoot)) {
		return errors.New(
			"FI generation roots must be distinct from batch/recovery custody root",
		)
	}

	if config.GenerationMaxCanonicalBytes > uint64(1<<63-1) ||
		config.GenerationMaxEncodedBytes > uint64(1<<63-1) {
		return errors.New(
			"FI generation listener transport limits exceed structural safety bounds",
		)
	}

	if config.GenerationMaxManifestBytes > 64<<20 {
		return errors.New(
			"FI generation listener manifest limit exceeds semantic safety bound",
		)
	}

	return nil
}

func validateGenerationReceiveConfig(
	config GenerationReceiveConfig,
) error {
	if config.Custody.RootDir == "" {
		return errors.New(
			"FI generation durable custody root directory is required",
		)
	}

	if config.Custody.Receive.Source.SourceID == "" {
		return errors.New(
			"FI generation source authorization is required",
		)
	}

	if config.Custody.Receive.MaxCanonicalBytes == 0 {
		return errors.New(
			"FI generation maximum canonical byte count must be greater than zero",
		)
	}

	if config.Custody.Receive.MaxEncodedBytes == 0 {
		return errors.New(
			"FI generation maximum encoded byte count must be greater than zero",
		)
	}

	if config.Recorder.RootDir == "" {
		return errors.New(
			"FI generation recorder root directory is required",
		)
	}

	if config.ReadyRoot == "" {
		return errors.New(
			"FI generation ingest-ready root directory is required",
		)
	}
	if !filepath.IsAbs(config.ReadyRoot) {
		return errors.New(
			"FI generation ingest-ready root directory must be absolute",
		)
	}
	if filepath.Clean(config.ReadyRoot) == filepath.Clean(config.Custody.RootDir) ||
		filepath.Clean(config.ReadyRoot) == filepath.Clean(config.Recorder.RootDir) {
		return errors.New(
			"FI generation ingest-ready root must be distinct from custody and recorder roots",
		)
	}

	if config.Recorder.Semantic.MaxManifestBytes == 0 {
		return errors.New(
			"FI generation recorder maximum manifest byte count must be greater than zero",
		)
	}

	return nil
}
