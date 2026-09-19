// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package transportrecovery

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	OfferMagic           = "FIRO0001"
	DecisionMagic        = "FIRA0001"
	AcknowledgementMagic = "FIRK0001"
	controlMaxBytes      = uint32(64 << 10)
)

type Offer struct {
	Version               string `json:"version"`
	SourceID              string `json:"source_id"`
	PendingMembers        uint64 `json:"pending_members"`
	PendingCanonicalBytes uint64 `json:"pending_canonical_bytes"`
	OldestBatchID         string `json:"oldest_batch_id"`
	NewestBatchID         string `json:"newest_batch_id"`
	ProposedMembers       uint64 `json:"proposed_members"`
}

type Decision struct {
	Version           string `json:"version"`
	Accepted          bool   `json:"accepted"`
	Reason            string `json:"reason,omitempty"`
	MaxCanonicalBytes uint64 `json:"max_canonical_bytes,omitempty"`
	MaxEncodedBytes   uint64 `json:"max_encoded_bytes,omitempty"`
	MaxMembers        uint64 `json:"max_members,omitempty"`
}

type AcknowledgementOutcome string

const (
	AcknowledgementDurableNew       AcknowledgementOutcome = "DURABLE_RECOVERY_NEW"
	AcknowledgementDurableDuplicate AcknowledgementOutcome = "DURABLE_RECOVERY_DUPLICATE"
)

type Acknowledgement struct {
	Version           string                 `json:"version"`
	Outcome           AcknowledgementOutcome `json:"outcome"`
	SourceID          string                 `json:"source_id"`
	RecoveryID        string                 `json:"recovery_id"`
	MemberCount       uint64                 `json:"member_count"`
	CanonicalBytes    uint64                 `json:"canonical_bytes"`
	CanonicalSHA256   string                 `json:"canonical_sha256"`
	EncodedDataBytes  uint64                 `json:"encoded_data_bytes"`
	EncodedDataSHA256 string                 `json:"encoded_data_sha256"`
	IndexSHA256       string                 `json:"index_sha256"`
	FirstBatchID      string                 `json:"first_batch_id"`
	LastBatchID       string                 `json:"last_batch_id"`
	FrameBytes        uint64                 `json:"frame_bytes"`
	FrameSHA256       string                 `json:"frame_sha256"`
}

func (offer Offer) Validate() error {
	if offer.Version != "fi-recovery-offer/0.1" {
		return errors.New("unsupported recovery offer version")
	}
	if strings.TrimSpace(offer.SourceID) == "" || strings.ContainsAny(offer.SourceID, "\x00\r\n") || offer.PendingMembers == 0 || offer.PendingCanonicalBytes == 0 {
		return errors.New("recovery offer is incomplete")
	}
	if strings.TrimSpace(offer.OldestBatchID) == "" || strings.TrimSpace(offer.NewestBatchID) == "" || strings.ContainsAny(offer.OldestBatchID+offer.NewestBatchID, "\x00\r\n") {
		return errors.New("recovery offer batch range is incomplete")
	}
	if offer.OldestBatchID > offer.NewestBatchID {
		return errors.New("recovery offer batch range is not oldest-first")
	}
	if offer.ProposedMembers == 0 || offer.ProposedMembers > offer.PendingMembers {
		return errors.New("recovery offer proposed member count is invalid")
	}
	return nil
}

func (decision Decision) Validate() error {
	if decision.Version != "fi-recovery-decision/0.1" {
		return errors.New("unsupported recovery decision version")
	}
	if !decision.Accepted {
		if strings.TrimSpace(decision.Reason) == "" {
			return errors.New("rejected recovery decision requires a reason")
		}
		return nil
	}
	if decision.MaxCanonicalBytes == 0 || decision.MaxEncodedBytes == 0 || decision.MaxMembers == 0 {
		return errors.New("accepted recovery decision requires non-zero limits")
	}
	if decision.MaxCanonicalBytes > maxSignedStreamingBytes || decision.MaxEncodedBytes > maxSignedStreamingBytes || decision.MaxMembers > maxRecoveryMembers {
		return errors.New("accepted recovery decision exceeds structural safety bounds")
	}
	return nil
}

func (ack Acknowledgement) Validate() error {
	if ack.Version != "fi-recovery-ack/0.1" {
		return errors.New("unsupported recovery acknowledgement version")
	}
	switch ack.Outcome {
	case AcknowledgementDurableNew, AcknowledgementDurableDuplicate:
	default:
		return fmt.Errorf("unsupported recovery acknowledgement outcome %q", ack.Outcome)
	}
	if strings.TrimSpace(ack.SourceID) == "" || strings.TrimSpace(ack.RecoveryID) == "" || ack.MemberCount == 0 {
		return errors.New("recovery acknowledgement identity is incomplete")
	}
	if ack.CanonicalBytes == 0 || ack.EncodedDataBytes == 0 || ack.FrameBytes == 0 {
		return errors.New("recovery acknowledgement byte counts must be greater than zero")
	}
	for _, value := range []struct {
		name string
		sha  string
	}{
		{name: "canonical SHA-256", sha: ack.CanonicalSHA256},
		{name: "encoded SHA-256", sha: ack.EncodedDataSHA256},
		{name: "index SHA-256", sha: ack.IndexSHA256},
		{name: "frame SHA-256", sha: ack.FrameSHA256},
	} {
		if err := validateSHA256(value.name, value.sha); err != nil {
			return err
		}
	}
	if ack.FirstBatchID == "" || ack.LastBatchID == "" {
		return errors.New("recovery acknowledgement batch range is incomplete")
	}
	if ack.FirstBatchID > ack.LastBatchID {
		return errors.New("recovery acknowledgement batch range is not oldest-first")
	}
	if ack.MemberCount > maxRecoveryMembers || ack.CanonicalBytes > maxSignedStreamingBytes || ack.EncodedDataBytes > maxSignedStreamingBytes || ack.FrameBytes > maxSignedStreamingBytes {
		return errors.New("recovery acknowledgement exceeds structural safety bounds")
	}
	return nil
}

func WriteOffer(writer io.Writer, offer Offer) error {
	if err := offer.Validate(); err != nil {
		return err
	}
	return writeControl(writer, OfferMagic, offer)
}

func ReadOffer(reader io.Reader) (Offer, error) {
	var value Offer
	if err := readControl(reader, OfferMagic, &value); err != nil {
		return Offer{}, err
	}
	if err := value.Validate(); err != nil {
		return Offer{}, err
	}
	return value, nil
}

func WriteDecision(writer io.Writer, decision Decision) error {
	if err := decision.Validate(); err != nil {
		return err
	}
	return writeControl(writer, DecisionMagic, decision)
}

func ReadDecision(reader io.Reader) (Decision, error) {
	var value Decision
	if err := readControl(reader, DecisionMagic, &value); err != nil {
		return Decision{}, err
	}
	if err := value.Validate(); err != nil {
		return Decision{}, err
	}
	return value, nil
}

func WriteAcknowledgement(writer io.Writer, acknowledgement Acknowledgement) error {
	if err := acknowledgement.Validate(); err != nil {
		return err
	}
	return writeControl(writer, AcknowledgementMagic, acknowledgement)
}

func ReadAcknowledgement(reader io.Reader) (Acknowledgement, error) {
	var value Acknowledgement
	if err := readControl(reader, AcknowledgementMagic, &value); err != nil {
		return Acknowledgement{}, err
	}
	if err := value.Validate(); err != nil {
		return Acknowledgement{}, err
	}
	return value, nil
}

func AcknowledgementMatches(ack Acknowledgement, descriptor Descriptor, frameBytes uint64, frameSHA256 string) error {
	if err := ack.Validate(); err != nil {
		return err
	}
	if err := descriptor.Validate(); err != nil {
		return err
	}
	if ack.SourceID != descriptor.SourceID || ack.RecoveryID != descriptor.RecoveryID || ack.MemberCount != descriptor.MemberCount {
		return errors.New("recovery acknowledgement identity does not match sent recovery descriptor")
	}
	if ack.CanonicalBytes != descriptor.CanonicalBytes || ack.CanonicalSHA256 != descriptor.CanonicalSHA256 {
		return errors.New("recovery acknowledgement canonical facts do not match sent descriptor")
	}
	if ack.EncodedDataBytes != descriptor.EncodedDataBytes || ack.EncodedDataSHA256 != descriptor.EncodedDataSHA256 {
		return errors.New("recovery acknowledgement encoded facts do not match sent descriptor")
	}
	if ack.IndexSHA256 != descriptor.IndexSHA256 || ack.FirstBatchID != descriptor.FirstBatchID || ack.LastBatchID != descriptor.LastBatchID {
		return errors.New("recovery acknowledgement member index facts do not match sent descriptor")
	}
	if ack.FrameBytes != frameBytes || ack.FrameSHA256 != frameSHA256 {
		return errors.New("recovery acknowledgement exact frame facts do not match sent frame")
	}
	return nil
}

func writeControl(writer io.Writer, magic string, value any) error {
	if writer == nil {
		return errors.New("recovery control writer is required")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(encoded) == 0 || len(encoded) > int(controlMaxBytes) {
		return errors.New("recovery control message exceeds size bound")
	}
	if _, err := io.WriteString(writer, magic); err != nil {
		return err
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(encoded)))
	if _, err := writer.Write(length[:]); err != nil {
		return err
	}
	_, err = writer.Write(encoded)
	return err
}

func readControl(reader io.Reader, magic string, destination any) error {
	if reader == nil {
		return errors.New("recovery control reader is required")
	}
	var actualMagic [8]byte
	if _, err := io.ReadFull(reader, actualMagic[:]); err != nil {
		return err
	}
	if string(actualMagic[:]) != magic {
		return fmt.Errorf("recovery control magic must be %q", magic)
	}
	var length [4]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(length[:])
	if size == 0 || size > controlMaxBytes {
		return errors.New("recovery control payload size is outside bounds")
	}
	encoded := make([]byte, int(size))
	if _, err := io.ReadFull(reader, encoded); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytesReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("recovery control message contains trailing JSON")
	}
	return nil
}
