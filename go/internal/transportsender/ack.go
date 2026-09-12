// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportsender

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportack"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportbatch"
)

// SentFrame identifies the exact FI wire frame whose durable acknowledgement is
// expected from the receiver. Descriptor binds the published Phase 1 batch;
// FrameBytes and FrameSHA256 bind the exact serialized frame that was sent.
type SentFrame struct {
	Descriptor  transportbatch.Descriptor
	FrameBytes  uint64
	FrameSHA256 string
}

// RetirementAuthorization is produced only after a complete durable receiver
// acknowledgement matches the exact FI frame sent by this source.
//
// The zero value is not valid authorization. A later source-spool retirement
// operation may use this type as its prerequisite instead of accepting a bare
// boolean or unverified acknowledgement.
type RetirementAuthorization struct {
	acknowledgement transportack.Acknowledgement
}

// Acknowledgement returns the receiver acknowledgement that produced this
// retirement authorization. It is intended for audit/status reporting; callers
// must not construct retirement authority from an acknowledgement directly.
func (value RetirementAuthorization) Acknowledgement() (transportack.Acknowledgement, error) {
	if err := value.validate(); err != nil {
		return transportack.Acknowledgement{}, err
	}
	return value.acknowledgement, nil
}

// VerifyDurableAcknowledgement reads exactly one FI acknowledgement and verifies
// that every custody fact matches the exact frame the source sent.
//
// Only a complete DURABLE_NEW or DURABLE_DUPLICATE acknowledgement can produce
// RetirementAuthorization. Any mismatch leaves source custody authoritative.
func VerifyDurableAcknowledgement(
	reader io.Reader,
	sent SentFrame,
) (RetirementAuthorization, error) {
	if reader == nil {
		return RetirementAuthorization{}, errors.New("acknowledgement reader is required")
	}
	if err := sent.Validate(); err != nil {
		return RetirementAuthorization{}, fmt.Errorf("validate sent FI frame: %w", err)
	}

	acknowledgement, err := transportack.ReadAcknowledgement(reader)
	if err != nil {
		return RetirementAuthorization{}, fmt.Errorf("read FI durable acknowledgement: %w", err)
	}

	if err := acknowledgementMatchesSentFrame(acknowledgement, sent); err != nil {
		return RetirementAuthorization{}, err
	}

	return RetirementAuthorization{
		acknowledgement: acknowledgement,
	}, nil
}

// Validate verifies the source-side facts required before an acknowledgement
// can be trusted to authorize retirement of the corresponding local batch.
func (value SentFrame) Validate() error {
	if err := value.Descriptor.Validate(); err != nil {
		return fmt.Errorf("validate transport descriptor: %w", err)
	}
	if value.FrameBytes == 0 {
		return errors.New("sent FI frame byte count must be greater than zero")
	}
	if err := validateFrameSHA256(value.FrameSHA256); err != nil {
		return err
	}
	return nil
}

func acknowledgementMatchesSentFrame(
	acknowledgement transportack.Acknowledgement,
	sent SentFrame,
) error {
	descriptor := sent.Descriptor

	if acknowledgement.SourceID != descriptor.SourceID {
		return fmt.Errorf(
			"acknowledgement source ID %q does not match sent source ID %q",
			acknowledgement.SourceID,
			descriptor.SourceID,
		)
	}
	if acknowledgement.BatchID != descriptor.BatchID {
		return fmt.Errorf(
			"acknowledgement batch ID %q does not match sent batch ID %q",
			acknowledgement.BatchID,
			descriptor.BatchID,
		)
	}
	if acknowledgement.DataBytes != descriptor.DataBytes {
		return fmt.Errorf(
			"acknowledgement data byte count %d does not match sent data byte count %d",
			acknowledgement.DataBytes,
			descriptor.DataBytes,
		)
	}
	if acknowledgement.DataSHA256 != descriptor.DataSHA256 {
		return errors.New(
			"acknowledgement data SHA-256 does not match sent descriptor",
		)
	}
	if acknowledgement.ManifestSHA256 != descriptor.ManifestSHA256 {
		return errors.New(
			"acknowledgement manifest SHA-256 does not match sent descriptor",
		)
	}
	if acknowledgement.FrameBytes != sent.FrameBytes {
		return fmt.Errorf(
			"acknowledgement frame byte count %d does not match sent frame byte count %d",
			acknowledgement.FrameBytes,
			sent.FrameBytes,
		)
	}
	if acknowledgement.FrameSHA256 != sent.FrameSHA256 {
		return errors.New(
			"acknowledgement frame SHA-256 does not match exact sent frame",
		)
	}

	return nil
}

func (value RetirementAuthorization) validate() error {
	if err := value.acknowledgement.Validate(); err != nil {
		return fmt.Errorf("retirement authorization acknowledgement is invalid: %w", err)
	}
	return nil
}

func validateFrameSHA256(value string) error {
	if len(value) != 64 {
		return errors.New("sent FI frame SHA-256 must contain 64 lowercase hexadecimal characters")
	}
	if value != strings.ToLower(value) {
		return errors.New("sent FI frame SHA-256 must use lowercase hexadecimal")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return fmt.Errorf("sent FI frame SHA-256 is invalid hexadecimal: %w", err)
	}
	if len(decoded) != 32 {
		return errors.New("sent FI frame SHA-256 must decode to 32 bytes")
	}
	return nil
}
