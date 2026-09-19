// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportgeneration

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	OfferMagic = "FIGO0001"

	DecisionMagic = "FIGD0001"

	AcknowledgementMagic = "FIGA0001"

	OfferVersion = "fi-generation-offer/0.1"

	DecisionVersion = "fi-generation-decision/0.1"

	AcknowledgementVersion = "fi-generation-acknowledgement/0.1"

	AcknowledgementOutcomeRecorded = "recorded"

	AcknowledgementOutcomeAlreadyRecorded = "already_recorded"

	protocolHeaderBytes = 12

	maxProtocolJSONBytes = 64 << 10
)

type Offer struct {
	Version string `json:"version"`

	Descriptor Descriptor `json:"descriptor"`

	MetadataBytes  uint64 `json:"metadata_bytes"`
	MetadataSHA256 string `json:"metadata_sha256"`
}

type Decision struct {
	Version string `json:"version"`

	SourceID     string `json:"source_id"`
	GenerationID string `json:"generation_id"`

	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"`
}

type Acknowledgement struct {
	Version string `json:"version"`

	Outcome string `json:"outcome"`

	Descriptor Descriptor `json:"descriptor"`

	MetadataBytes  uint64 `json:"metadata_bytes"`
	MetadataSHA256 string `json:"metadata_sha256"`

	TransferBytes  uint64 `json:"transfer_bytes"`
	TransferSHA256 string `json:"transfer_sha256"`
}

// OfferFromPublished constructs an admission offer using only the durable
// signed metadata and structural payload facts.
//
// It deliberately does not reread or hash the encoded payload. The encoded
// payload SHA-256 is already signed in Descriptor and is verified during the
// same payload read used for transport.
func OfferFromPublished(
	generation PublishedGeneration,
) (
	Offer,
	error,
) {
	if generation.DirectoryPath == "" ||
		generation.MetadataPath == "" ||
		generation.PayloadPath == "" {
		return Offer{},
			errors.New(
				"FI published generation paths are incomplete",
			)
	}

	current, err :=
		LoadSealedGeneration(
			generation.DirectoryPath,
		)
	if err != nil {
		return Offer{},
			fmt.Errorf(
				"reload FI generation for offer: %w",
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
		return Offer{},
			errors.New(
				"FI published generation changed before offer",
			)
	}

	metadata, err :=
		readStableBoundedGenerationFile(
			current.MetadataPath,
			maxSignedGenerationMetadataBytes,
		)
	if err != nil {
		return Offer{},
			fmt.Errorf(
				"read FI generation metadata for offer: %w",
				err,
			)
	}

	decoded, err :=
		UnmarshalSignedGeneration(
			metadata,
		)
	if err != nil {
		return Offer{}, err
	}

	if !signedGenerationsEqual(
		decoded,
		current.Signed,
	) {
		return Offer{},
			errors.New(
				"FI generation metadata changed before offer",
			)
	}

	digest :=
		sha256.Sum256(
			metadata,
		)

	offer :=
		Offer{
			Version: OfferVersion,

			Descriptor: current.Signed.Descriptor,

			MetadataBytes: uint64(
				len(metadata),
			),

			MetadataSHA256: hex.EncodeToString(
				digest[:],
			),
		}

	if err :=
		offer.Validate(); err != nil {
		return Offer{}, err
	}

	return offer, nil
}

func (
	offer Offer,
) Validate() error {
	if offer.Version !=
		OfferVersion {
		return errors.New(
			"invalid FI generation offer version",
		)
	}

	if err :=
		offer.Descriptor.Validate(); err != nil {
		return fmt.Errorf(
			"invalid FI generation offer descriptor: %w",
			err,
		)
	}

	if offer.MetadataBytes == 0 ||
		offer.MetadataBytes >
			uint64(
				maxSignedGenerationMetadataBytes,
			) {
		return errors.New(
			"FI generation offer metadata byte count is outside bounds",
		)
	}

	if err :=
		validateSHA256(
			"metadata SHA-256",
			offer.MetadataSHA256,
		); err != nil {
		return err
	}

	return nil
}

func NewDecision(
	offer Offer,
	accepted bool,
	reason string,
) (
	Decision,
	error,
) {
	if err :=
		offer.Validate(); err != nil {
		return Decision{}, err
	}

	decision :=
		Decision{
			Version: DecisionVersion,

			SourceID: offer.Descriptor.SourceID,

			GenerationID: offer.Descriptor.GenerationID,

			Accepted: accepted,

			Reason: reason,
		}

	if err :=
		decision.Validate(); err != nil {
		return Decision{}, err
	}

	return decision, nil
}

func (
	decision Decision,
) Validate() error {
	if decision.Version !=
		DecisionVersion {
		return errors.New(
			"invalid FI generation decision version",
		)
	}

	if err :=
		validateTextIdentity(
			"source ID",
			decision.SourceID,
		); err != nil {
		return err
	}

	if err :=
		validateTextIdentity(
			"generation ID",
			decision.GenerationID,
		); err != nil {
		return err
	}

	if bytes.ContainsAny(
		[]byte(
			decision.GenerationID,
		),
		"/\\",
	) {
		return errors.New(
			"generation ID must not contain path separators",
		)
	}

	if decision.Accepted {
		if decision.Reason != "" {
			return errors.New(
				"accepted FI generation decision must not include a rejection reason",
			)
		}

		return nil
	}

	if err :=
		validateTextIdentity(
			"decision reason",
			decision.Reason,
		); err != nil {
		return errors.New(
			"rejected FI generation decision requires a valid reason",
		)
	}

	return nil
}

func DecisionMatchesOffer(
	decision Decision,
	offer Offer,
) error {
	if err :=
		decision.Validate(); err != nil {
		return err
	}

	if err :=
		offer.Validate(); err != nil {
		return err
	}

	if decision.SourceID !=
		offer.Descriptor.SourceID ||
		decision.GenerationID !=
			offer.Descriptor.GenerationID {
		return errors.New(
			"FI generation decision does not match offered generation identity",
		)
	}

	return nil
}

func NewAcknowledgement(
	outcome string,
	result TransferResult,
) (
	Acknowledgement,
	error,
) {
	acknowledgement :=
		Acknowledgement{
			Version: AcknowledgementVersion,

			Outcome: outcome,

			Descriptor: result.Descriptor,

			MetadataBytes: result.MetadataBytes,

			MetadataSHA256: result.MetadataSHA256,

			TransferBytes: result.TransferBytes,

			TransferSHA256: result.TransferSHA256,
		}

	if err :=
		acknowledgement.Validate(); err != nil {
		return Acknowledgement{}, err
	}

	return acknowledgement, nil
}

func (
	acknowledgement Acknowledgement,
) Validate() error {
	if acknowledgement.Version !=
		AcknowledgementVersion {
		return errors.New(
			"invalid FI generation acknowledgement version",
		)
	}

	switch acknowledgement.Outcome {
	case AcknowledgementOutcomeRecorded,
		AcknowledgementOutcomeAlreadyRecorded:

	default:
		return errors.New(
			"invalid FI generation acknowledgement outcome",
		)
	}

	if err :=
		acknowledgement.Descriptor.Validate(); err != nil {
		return fmt.Errorf(
			"invalid FI generation acknowledgement descriptor: %w",
			err,
		)
	}

	if acknowledgement.MetadataBytes == 0 ||
		acknowledgement.MetadataBytes >
			uint64(
				maxSignedGenerationMetadataBytes,
			) {
		return errors.New(
			"FI generation acknowledgement metadata byte count is outside bounds",
		)
	}

	if err :=
		validateSHA256(
			"metadata SHA-256",
			acknowledgement.MetadataSHA256,
		); err != nil {
		return err
	}

	if err :=
		validateSHA256(
			"transfer SHA-256",
			acknowledgement.TransferSHA256,
		); err != nil {
		return err
	}

	expectedTransferBytes :=
		uint64(
			transferHeaderBytes,
		)

	if acknowledgement.MetadataBytes >
		^uint64(0)-
			expectedTransferBytes {
		return errors.New(
			"FI generation acknowledgement transfer byte count overflow",
		)
	}

	expectedTransferBytes +=
		acknowledgement.MetadataBytes

	if acknowledgement.Descriptor.EncodedDataBytes >
		^uint64(0)-
			expectedTransferBytes {
		return errors.New(
			"FI generation acknowledgement transfer byte count overflow",
		)
	}

	expectedTransferBytes +=
		acknowledgement.Descriptor.EncodedDataBytes

	if acknowledgement.TransferBytes !=
		expectedTransferBytes {
		return errors.New(
			"FI generation acknowledgement transfer byte count is inconsistent",
		)
	}

	return nil
}

func AcknowledgementMatches(
	acknowledgement Acknowledgement,
	result TransferResult,
) error {
	if err :=
		acknowledgement.Validate(); err != nil {
		return err
	}

	if err :=
		result.Descriptor.Validate(); err != nil {
		return fmt.Errorf(
			"invalid FI generation transfer result descriptor: %w",
			err,
		)
	}

	if acknowledgement.Descriptor !=
		result.Descriptor {
		return errors.New(
			"FI generation acknowledgement descriptor does not match transmitted generation",
		)
	}

	if acknowledgement.MetadataBytes !=
		result.MetadataBytes ||
		acknowledgement.MetadataSHA256 !=
			result.MetadataSHA256 {
		return errors.New(
			"FI generation acknowledgement metadata identity does not match transmitted generation",
		)
	}

	if acknowledgement.TransferBytes !=
		result.TransferBytes ||
		acknowledgement.TransferSHA256 !=
			result.TransferSHA256 {
		return errors.New(
			"FI generation acknowledgement transfer identity does not match transmitted generation",
		)
	}

	return nil
}

func WriteOffer(
	writer io.Writer,
	offer Offer,
) error {
	if err :=
		offer.Validate(); err != nil {
		return err
	}

	return writeProtocolJSON(
		writer,
		OfferMagic,
		offer,
	)
}

func ReadOffer(
	reader io.Reader,
) (
	Offer,
	error,
) {
	var offer Offer

	if err :=
		readProtocolJSON(
			reader,
			OfferMagic,
			&offer,
		); err != nil {
		return Offer{}, err
	}

	if err :=
		offer.Validate(); err != nil {
		return Offer{}, err
	}

	return offer, nil
}

func WriteDecision(
	writer io.Writer,
	decision Decision,
) error {
	if err :=
		decision.Validate(); err != nil {
		return err
	}

	return writeProtocolJSON(
		writer,
		DecisionMagic,
		decision,
	)
}

func ReadDecision(
	reader io.Reader,
) (
	Decision,
	error,
) {
	var decision Decision

	if err :=
		readProtocolJSON(
			reader,
			DecisionMagic,
			&decision,
		); err != nil {
		return Decision{}, err
	}

	if err :=
		decision.Validate(); err != nil {
		return Decision{}, err
	}

	return decision, nil
}

func WriteAcknowledgement(
	writer io.Writer,
	acknowledgement Acknowledgement,
) error {
	if err :=
		acknowledgement.Validate(); err != nil {
		return err
	}

	return writeProtocolJSON(
		writer,
		AcknowledgementMagic,
		acknowledgement,
	)
}

func ReadAcknowledgement(
	reader io.Reader,
) (
	Acknowledgement,
	error,
) {
	var acknowledgement Acknowledgement

	if err :=
		readProtocolJSON(
			reader,
			AcknowledgementMagic,
			&acknowledgement,
		); err != nil {
		return Acknowledgement{}, err
	}

	if err :=
		acknowledgement.Validate(); err != nil {
		return Acknowledgement{}, err
	}

	return acknowledgement, nil
}

func writeProtocolJSON(
	writer io.Writer,
	magic string,
	value any,
) error {
	if writer == nil {
		return errors.New(
			"FI generation protocol writer is required",
		)
	}

	if len(magic) != 8 {
		return errors.New(
			"FI generation protocol magic must be exactly 8 bytes",
		)
	}

	raw, err :=
		json.Marshal(
			value,
		)
	if err != nil {
		return err
	}

	if len(raw) == 0 ||
		len(raw) >
			maxProtocolJSONBytes {
		return errors.New(
			"FI generation protocol JSON size is outside bounds",
		)
	}

	var header [protocolHeaderBytes]byte

	copy(
		header[0:8],
		[]byte(
			magic,
		),
	)

	binary.BigEndian.PutUint32(
		header[8:12],
		uint32(
			len(raw),
		),
	)

	if err :=
		writeAllProtocol(
			writer,
			header[:],
		); err != nil {
		return err
	}

	return writeAllProtocol(
		writer,
		raw,
	)
}

func readProtocolJSON(
	reader io.Reader,
	expectedMagic string,
	destination any,
) error {
	if reader == nil {
		return errors.New(
			"FI generation protocol reader is required",
		)
	}

	if destination == nil {
		return errors.New(
			"FI generation protocol destination is required",
		)
	}

	var header [protocolHeaderBytes]byte

	if _,
		err :=
		io.ReadFull(
			reader,
			header[:],
		); err != nil {
		return fmt.Errorf(
			"read FI generation protocol header: %w",
			err,
		)
	}

	if string(
		header[0:8],
	) != expectedMagic {
		return errors.New(
			"unexpected FI generation protocol magic",
		)
	}

	length :=
		binary.BigEndian.Uint32(
			header[8:12],
		)

	if length == 0 ||
		length >
			uint32(
				maxProtocolJSONBytes,
			) {
		return errors.New(
			"FI generation protocol JSON length is outside bounds",
		)
	}

	raw :=
		make(
			[]byte,
			int(length),
		)

	if _,
		err :=
		io.ReadFull(
			reader,
			raw,
		); err != nil {
		return fmt.Errorf(
			"read FI generation protocol JSON: %w",
			err,
		)
	}

	decoder :=
		json.NewDecoder(
			bytes.NewReader(
				raw,
			),
		)

	decoder.DisallowUnknownFields()

	if err :=
		decoder.Decode(
			destination,
		); err != nil {
		return fmt.Errorf(
			"decode FI generation protocol JSON: %w",
			err,
		)
	}

	var extra any

	if err :=
		decoder.Decode(
			&extra,
		); err != io.EOF {
		return errors.New(
			"FI generation protocol JSON contains trailing content",
		)
	}

	return nil
}

func writeAllProtocol(
	writer io.Writer,
	value []byte,
) error {
	for len(value) > 0 {
		written, err :=
			writer.Write(
				value,
			)

		if err != nil {
			return err
		}

		if written <= 0 ||
			written >
				len(value) {
			return io.ErrShortWrite
		}

		value =
			value[written:]
	}

	return nil
}
