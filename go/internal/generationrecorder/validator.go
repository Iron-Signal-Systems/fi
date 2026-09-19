// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package generationrecorder

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

const maxSupportedManifestBytes = 64 << 20

type artifactKind uint8

const (
	artifactKindData artifactKind = iota + 1
	artifactKindManifest
)

// Config defines bounded semantic validation for one decoded FI generation.
type Config struct {
	MaxManifestBytes uint64
}

// Result summarizes one complete generation whose collector batch pairs passed
// the recorder semantic gate.
//
// This is NOT durable backend recording and MUST NOT cause a generation success
// acknowledgement or sender retirement by itself.
type Result struct {
	ArtifactCount uint64
	BatchCount    uint64
	DataBytes     uint64
	GenerationID  string
	RecordCount   uint64
	SourceBytes   uint64
	SourceID      string
}

type pendingBatch struct {
	batchID    string
	dataName   string
	inspection spool.DataInspection
}

type validator struct {
	batchCount  uint64
	config      Config
	dataBytes   uint64
	pending     *pendingBatch
	recordCount uint64
}

// ValidateCanonical applies the collector batch semantic contract to one
// already-decoded FI generation canonical stream.
//
// The transport-generation layer remains responsible for cryptographic trust,
// encoded/canonical hashes, and canonical framing. This layer requires every
// canonical artifact to form an exact batch-<id>.jsonl /
// batch-<id>.manifest.json pair and verifies each manifest against streaming
// facts computed from its paired data artifact.
func ValidateCanonical(
	reader io.Reader,
	descriptor transportgeneration.Descriptor,
	config Config,
) (
	Result,
	error,
) {
	if reader == nil {
		return Result{},
			errors.New(
				"FI generation recorder canonical reader is required",
			)
	}

	state, err :=
		newValidator(
			descriptor,
			config,
		)
	if err != nil {
		return Result{}, err
	}

	sourceBytes, err :=
		transportgeneration.ReadCanonicalArtifacts(
			reader,
			descriptor,
			state.consumeArtifact,
		)
	if err != nil {
		return Result{},
			fmt.Errorf(
				"validate FI generation recorder artifact stream: %w",
				err,
			)
	}

	return state.result(
		descriptor,
		sourceBytes,
	)
}

func newValidator(
	descriptor transportgeneration.Descriptor,
	config Config,
) (
	*validator,
	error,
) {
	if err :=
		validateConfig(
			config,
		); err != nil {
		return nil, err
	}

	if err :=
		descriptor.Validate(); err != nil {
		return nil,
			fmt.Errorf(
				"validate FI generation recorder descriptor: %w",
				err,
			)
	}

	if descriptor.ArtifactCount%2 != 0 {
		return nil,
			errors.New(
				"FI generation recorder requires an even artifact count for batch pairs",
			)
	}

	return &validator{
		config: config,
	}, nil
}

func (
	state *validator,
) result(
	descriptor transportgeneration.Descriptor,
	sourceBytes uint64,
) (
	Result,
	error,
) {
	if state == nil {
		return Result{},
			errors.New(
				"FI generation recorder validator state is required",
			)
	}

	if state.pending != nil {
		return Result{},
			fmt.Errorf(
				"FI generation batch %q is missing its manifest artifact",
				state.pending.batchID,
			)
	}

	if sourceBytes !=
		descriptor.SourceBytes {
		return Result{},
			fmt.Errorf(
				"FI generation recorder source byte count %d does not match signed descriptor %d",
				sourceBytes,
				descriptor.SourceBytes,
			)
	}

	if state.batchCount*2 !=
		descriptor.ArtifactCount {
		return Result{},
			errors.New(
				"FI generation recorder batch count does not match canonical artifact count",
			)
	}

	return Result{
		ArtifactCount: descriptor.ArtifactCount,

		BatchCount: state.batchCount,

		DataBytes: state.dataBytes,

		GenerationID: descriptor.GenerationID,

		RecordCount: state.recordCount,

		SourceBytes: sourceBytes,

		SourceID: descriptor.SourceID,
	}, nil
}

func (
	state *validator,
) consumeArtifact(
	name string,
	reader io.Reader,
) error {
	batchID, kind, err :=
		parseArtifactName(
			name,
		)
	if err != nil {
		return err
	}

	switch kind {
	case artifactKindData:
		return state.consumeData(
			batchID,
			name,
			reader,
		)

	case artifactKindManifest:
		return state.consumeManifest(
			batchID,
			name,
			reader,
		)

	default:
		return errors.New(
			"FI generation recorder artifact kind is unsupported",
		)
	}
}

func (
	state *validator,
) consumeData(
	batchID string,
	name string,
	reader io.Reader,
) error {
	if state.pending != nil {
		return fmt.Errorf(
			"FI generation batch %q data appeared before manifest for prior batch %q",
			batchID,
			state.pending.batchID,
		)
	}

	inspection, err :=
		spool.InspectData(
			reader,
		)
	if err != nil {
		return fmt.Errorf(
			"inspect FI generation batch %q data: %w",
			batchID,
			err,
		)
	}

	state.pending =
		&pendingBatch{
			batchID:    batchID,
			dataName:   name,
			inspection: inspection,
		}

	return nil
}

func (
	state *validator,
) consumeManifest(
	batchID string,
	name string,
	reader io.Reader,
) error {
	if state.pending == nil {
		return fmt.Errorf(
			"FI generation batch %q manifest has no preceding data artifact",
			batchID,
		)
	}

	if state.pending.batchID !=
		batchID {
		return fmt.Errorf(
			"FI generation manifest batch ID %q does not match preceding data batch ID %q",
			batchID,
			state.pending.batchID,
		)
	}

	manifestBytes, err :=
		readManifestBytes(
			reader,
			state.config.MaxManifestBytes,
		)
	if err != nil {
		return fmt.Errorf(
			"read FI generation batch %q manifest: %w",
			batchID,
			err,
		)
	}

	manifest, err :=
		spool.DecodeManifest(
			bytes.NewReader(
				manifestBytes,
			),
		)
	if err != nil {
		return fmt.Errorf(
			"decode FI generation batch %q manifest: %w",
			batchID,
			err,
		)
	}

	expectedManifestName :=
		"batch-" +
			manifest.BatchID +
			".manifest.json"

	if manifest.BatchID !=
		batchID ||
		name !=
			expectedManifestName {
		return errors.New(
			"FI generation manifest artifact identity does not match manifest batch ID",
		)
	}

	if manifest.DataFile !=
		state.pending.dataName {
		return errors.New(
			"FI generation manifest data_file does not match paired data artifact",
		)
	}

	if err :=
		spool.VerifyManifestData(
			manifest,
			state.pending.inspection,
		); err != nil {
		return fmt.Errorf(
			"verify FI generation batch %q manifest/data pair: %w",
			batchID,
			err,
		)
	}

	if state.pending.inspection.DataBytes < 0 {
		return errors.New(
			"FI generation batch data byte count is negative",
		)
	}

	dataBytes :=
		uint64(
			state.pending.inspection.DataBytes,
		)

	if dataBytes >
		^uint64(0)-
			state.dataBytes {
		return errors.New(
			"FI generation recorder data byte count overflow",
		)
	}

	if manifest.RecordCount < 0 {
		return errors.New(
			"FI generation batch record count is negative",
		)
	}

	recordCount :=
		uint64(
			manifest.RecordCount,
		)

	if recordCount >
		^uint64(0)-
			state.recordCount {
		return errors.New(
			"FI generation recorder record count overflow",
		)
	}

	if state.batchCount ==
		^uint64(0) {
		return errors.New(
			"FI generation recorder batch count overflow",
		)
	}

	state.batchCount++

	state.dataBytes +=
		dataBytes

	state.recordCount +=
		recordCount

	state.pending =
		nil

	return nil
}

func parseArtifactName(
	name string,
) (
	string,
	artifactKind,
	error,
) {
	if !strings.HasPrefix(
		name,
		"batch-",
	) {
		return "",
			0,
			fmt.Errorf(
				"unexpected FI generation recorder artifact %q",
				name,
			)
	}

	switch {
	case strings.HasSuffix(
		name,
		".jsonl",
	):
		batchID :=
			strings.TrimSuffix(
				strings.TrimPrefix(
					name,
					"batch-",
				),
				".jsonl",
			)

		if batchID == "" {
			return "",
				0,
				errors.New(
					"FI generation data artifact has an empty batch ID",
				)
		}

		return batchID,
			artifactKindData,
			nil

	case strings.HasSuffix(
		name,
		".manifest.json",
	):
		batchID :=
			strings.TrimSuffix(
				strings.TrimPrefix(
					name,
					"batch-",
				),
				".manifest.json",
			)

		if batchID == "" {
			return "",
				0,
				errors.New(
					"FI generation manifest artifact has an empty batch ID",
				)
		}

		return batchID,
			artifactKindManifest,
			nil

	default:
		return "",
			0,
			fmt.Errorf(
				"unexpected FI generation recorder artifact %q",
				name,
			)
	}
}

func readManifestBytes(
	reader io.Reader,
	maximum uint64,
) (
	[]byte,
	error,
) {
	if maximum == 0 ||
		maximum >
			maxSupportedManifestBytes {
		return nil,
			errors.New(
				"FI generation recorder manifest byte limit is outside supported bounds",
			)
	}

	limited :=
		&io.LimitedReader{
			R: reader,
			N: int64(
				maximum + 1,
			),
		}

	value, err :=
		io.ReadAll(
			limited,
		)
	if err != nil {
		return nil, err
	}

	if uint64(
		len(value),
	) > maximum {
		return nil,
			errors.New(
				"FI generation recorder manifest exceeds configured byte limit",
			)
	}

	return value, nil
}

func validateConfig(
	config Config,
) error {
	if config.MaxManifestBytes == 0 ||
		config.MaxManifestBytes >
			maxSupportedManifestBytes {
		return fmt.Errorf(
			"FI generation recorder maximum manifest bytes must be between 1 and %d",
			maxSupportedManifestBytes,
		)
	}

	return nil
}
