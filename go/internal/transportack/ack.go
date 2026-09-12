// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportack

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	fixedAcknowledgementBytes = 136
	wireMagic                 = "FIACK001"

	AcknowledgementVersion = "fi-transport-ack/0.1"
	MaxOutcomeBytes        = 32
	MaxTextBytes           = 4 * 1024
	MaxVersionBytes        = 64
)

// Outcome identifies the only successful durable receiver outcomes that may be
// acknowledged to an FI source.
type Outcome string

const (
	OutcomeDurableDuplicate Outcome = "DURABLE_DUPLICATE"
	OutcomeDurableNew       Outcome = "DURABLE_NEW"
)

// Acknowledgement is the bounded success contract returned to a source only
// after receiver custody has become durable.
//
// There is deliberately no success value for a conflicting duplicate. Conflict,
// validation failure, and storage failure must never be representable as a
// successful acknowledgement.
type Acknowledgement struct {
	Version        string
	Outcome        Outcome
	SourceID       string
	BatchID        string
	DataBytes      uint64
	DataSHA256     string
	ManifestSHA256 string
	FrameBytes     uint64
	FrameSHA256    string
}

// NewDurableAcknowledgement constructs one success acknowledgement from a
// completed receiver-custody result. The caller supplies only the custody facts
// that are meaningful to the source; receiver-local paths are intentionally not
// part of the protocol.
func NewDurableAcknowledgement(
	outcome Outcome,
	sourceID string,
	batchID string,
	dataBytes uint64,
	dataSHA256 string,
	manifestSHA256 string,
	frameBytes uint64,
	frameSHA256 string,
) (Acknowledgement, error) {
	value := Acknowledgement{
		Version:        AcknowledgementVersion,
		Outcome:        outcome,
		SourceID:       sourceID,
		BatchID:        batchID,
		DataBytes:      dataBytes,
		DataSHA256:     dataSHA256,
		ManifestSHA256: manifestSHA256,
		FrameBytes:     frameBytes,
		FrameSHA256:    frameSHA256,
	}
	if err := value.Validate(); err != nil {
		return Acknowledgement{}, err
	}
	return value, nil
}

// ReadAcknowledgement reads exactly one bounded FI durable acknowledgement and
// leaves the reader positioned at the first byte after that acknowledgement.
func ReadAcknowledgement(reader io.Reader) (Acknowledgement, error) {
	if reader == nil {
		return Acknowledgement{}, errors.New("acknowledgement reader is required")
	}

	fixed := make([]byte, fixedAcknowledgementBytes)
	if _, err := io.ReadFull(reader, fixed); err != nil {
		return Acknowledgement{}, fmt.Errorf("read FI acknowledgement fixed header: %w", err)
	}
	if string(fixed[:len(wireMagic)]) != wireMagic {
		return Acknowledgement{}, errors.New("FI acknowledgement wire magic is invalid")
	}

	versionBytes := binary.BigEndian.Uint32(fixed[8:12])
	outcomeBytes := binary.BigEndian.Uint32(fixed[12:16])
	sourceIDBytes := binary.BigEndian.Uint32(fixed[16:20])
	batchIDBytes := binary.BigEndian.Uint32(fixed[20:24])
	dataBytes := binary.BigEndian.Uint64(fixed[24:32])
	frameBytes := binary.BigEndian.Uint64(fixed[32:40])

	if err := validateLengths(versionBytes, outcomeBytes, sourceIDBytes, batchIDBytes); err != nil {
		return Acknowledgement{}, err
	}

	version, err := readString(reader, versionBytes, "acknowledgement version")
	if err != nil {
		return Acknowledgement{}, err
	}
	outcome, err := readString(reader, outcomeBytes, "acknowledgement outcome")
	if err != nil {
		return Acknowledgement{}, err
	}
	sourceID, err := readString(reader, sourceIDBytes, "source ID")
	if err != nil {
		return Acknowledgement{}, err
	}
	batchID, err := readString(reader, batchIDBytes, "batch ID")
	if err != nil {
		return Acknowledgement{}, err
	}

	value := Acknowledgement{
		Version:        version,
		Outcome:        Outcome(outcome),
		SourceID:       sourceID,
		BatchID:        batchID,
		DataBytes:      dataBytes,
		DataSHA256:     hex.EncodeToString(fixed[40:72]),
		ManifestSHA256: hex.EncodeToString(fixed[72:104]),
		FrameBytes:     frameBytes,
		FrameSHA256:    hex.EncodeToString(fixed[104:136]),
	}
	if err := value.Validate(); err != nil {
		return Acknowledgement{}, fmt.Errorf("validate FI acknowledgement: %w", err)
	}

	return value, nil
}

// Validate verifies the success-only acknowledgement contract. It does not
// establish transport authenticity by itself; acknowledgements are consumed on
// the already-authenticated FI transport connection.
func (value Acknowledgement) Validate() error {
	if value.Version != AcknowledgementVersion {
		return fmt.Errorf(
			"acknowledgement version must be %q, got %q",
			AcknowledgementVersion,
			value.Version,
		)
	}

	switch value.Outcome {
	case OutcomeDurableDuplicate:
	case OutcomeDurableNew:
	default:
		return fmt.Errorf("unsupported durable acknowledgement outcome %q", value.Outcome)
	}

	if value.SourceID == "" {
		return errors.New("acknowledgement source ID is required")
	}
	if len(value.SourceID) > MaxTextBytes {
		return fmt.Errorf("acknowledgement source ID exceeds %d bytes", MaxTextBytes)
	}
	if value.BatchID == "" {
		return errors.New("acknowledgement batch ID is required")
	}
	if len(value.BatchID) > MaxTextBytes {
		return fmt.Errorf("acknowledgement batch ID exceeds %d bytes", MaxTextBytes)
	}
	if value.DataBytes == 0 {
		return errors.New("acknowledgement data byte count must be greater than zero")
	}
	if value.FrameBytes == 0 {
		return errors.New("acknowledgement frame byte count must be greater than zero")
	}
	if err := validateSHA256(value.DataSHA256, "data SHA-256"); err != nil {
		return err
	}
	if err := validateSHA256(value.ManifestSHA256, "manifest SHA-256"); err != nil {
		return err
	}
	if err := validateSHA256(value.FrameSHA256, "frame SHA-256"); err != nil {
		return err
	}

	return nil
}

// WriteAcknowledgement writes one deterministic success acknowledgement. It
// emits no error-status frame; callers must not convert custody conflicts or
// failures into a successful acknowledgement.
func WriteAcknowledgement(writer io.Writer, value Acknowledgement) error {
	if writer == nil {
		return errors.New("acknowledgement writer is required")
	}
	if err := value.Validate(); err != nil {
		return fmt.Errorf("validate FI acknowledgement: %w", err)
	}

	dataDigest, err := decodeSHA256(value.DataSHA256, "data SHA-256")
	if err != nil {
		return err
	}
	manifestDigest, err := decodeSHA256(value.ManifestSHA256, "manifest SHA-256")
	if err != nil {
		return err
	}
	frameDigest, err := decodeSHA256(value.FrameSHA256, "frame SHA-256")
	if err != nil {
		return err
	}

	fixed := make([]byte, fixedAcknowledgementBytes)
	copy(fixed[:8], wireMagic)
	binary.BigEndian.PutUint32(fixed[8:12], uint32(len(value.Version)))
	binary.BigEndian.PutUint32(fixed[12:16], uint32(len(value.Outcome)))
	binary.BigEndian.PutUint32(fixed[16:20], uint32(len(value.SourceID)))
	binary.BigEndian.PutUint32(fixed[20:24], uint32(len(value.BatchID)))
	binary.BigEndian.PutUint64(fixed[24:32], value.DataBytes)
	binary.BigEndian.PutUint64(fixed[32:40], value.FrameBytes)
	copy(fixed[40:72], dataDigest)
	copy(fixed[72:104], manifestDigest)
	copy(fixed[104:136], frameDigest)

	parts := [][]byte{
		fixed,
		[]byte(value.Version),
		[]byte(value.Outcome),
		[]byte(value.SourceID),
		[]byte(value.BatchID),
	}
	for _, part := range parts {
		if err := writeFull(writer, part); err != nil {
			return fmt.Errorf("write FI acknowledgement: %w", err)
		}
	}

	return nil
}

func decodeSHA256(value string, name string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode acknowledgement %s: %w", name, err)
	}
	if len(decoded) != 32 {
		return nil, fmt.Errorf("acknowledgement %s must decode to 32 bytes", name)
	}
	return decoded, nil
}

func readString(reader io.Reader, length uint32, name string) (string, error) {
	value := make([]byte, int(length))
	if _, err := io.ReadFull(reader, value); err != nil {
		return "", fmt.Errorf("read acknowledgement %s: %w", name, err)
	}
	return string(value), nil
}

func validateLengths(
	versionBytes uint32,
	outcomeBytes uint32,
	sourceIDBytes uint32,
	batchIDBytes uint32,
) error {
	if versionBytes == 0 || versionBytes > MaxVersionBytes {
		return fmt.Errorf("acknowledgement version length is invalid: %d", versionBytes)
	}
	if outcomeBytes == 0 || outcomeBytes > MaxOutcomeBytes {
		return fmt.Errorf("acknowledgement outcome length is invalid: %d", outcomeBytes)
	}
	if sourceIDBytes == 0 || sourceIDBytes > MaxTextBytes {
		return fmt.Errorf("acknowledgement source ID length is invalid: %d", sourceIDBytes)
	}
	if batchIDBytes == 0 || batchIDBytes > MaxTextBytes {
		return fmt.Errorf("acknowledgement batch ID length is invalid: %d", batchIDBytes)
	}
	return nil
}

func validateSHA256(value string, name string) error {
	if len(value) != 64 {
		return fmt.Errorf("acknowledgement %s must contain 64 hexadecimal characters", name)
	}
	if value != strings.ToLower(value) {
		return fmt.Errorf("acknowledgement %s must use lowercase hexadecimal", name)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("acknowledgement %s is invalid hexadecimal: %w", name, err)
	}
	if len(decoded) != 32 {
		return fmt.Errorf("acknowledgement %s must decode to 32 bytes", name)
	}
	return nil
}

func writeFull(writer io.Writer, value []byte) error {
	for len(value) > 0 {
		written, err := writer.Write(value)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(value) {
			return io.ErrShortWrite
		}
		value = value[written:]
	}
	return nil
}
