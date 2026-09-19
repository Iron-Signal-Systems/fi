// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportreceiver

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportrecovery"
)

var ErrRecoveryNotEnabled = errors.New("FI receiver recovery is not enabled")

type RecoveryReceiveResult struct {
	Acknowledgement transportrecovery.Acknowledgement
	Custody         transportrecovery.CustodyResult
	Offer           transportrecovery.Offer
}

func receiveAuthenticatedRecovery(
	reader io.Reader,
	writer io.Writer,
	config Config,
	currentTime time.Time,
) (RecoveryReceiveResult, error) {
	offer, err := transportrecovery.ReadOffer(reader)
	if err != nil {
		return RecoveryReceiveResult{}, fmt.Errorf("read FI recovery offer: %w", err)
	}
	if offer.SourceID != config.Source.SourceID {
		decision := transportrecovery.Decision{
			Version:  "fi-recovery-decision/0.1",
			Accepted: false,
			Reason:   "SOURCE_ID_MISMATCH",
		}
		_ = transportrecovery.WriteDecision(writer, decision)
		return RecoveryReceiveResult{}, errors.New("FI recovery offer source does not match authorized source")
	}

	if config.RecoveryMaxCanonicalBytes == 0 || config.RecoveryMaxEncodedBytes == 0 || config.RecoveryMaxMembers < 2 {
		decision := transportrecovery.Decision{
			Version:  "fi-recovery-decision/0.1",
			Accepted: false,
			Reason:   "RECOVERY_DISABLED",
		}
		if err := transportrecovery.WriteDecision(writer, decision); err != nil {
			return RecoveryReceiveResult{}, err
		}
		return RecoveryReceiveResult{Offer: offer}, ErrRecoveryNotEnabled
	}

	decision := transportrecovery.Decision{
		Version:           "fi-recovery-decision/0.1",
		Accepted:          true,
		MaxCanonicalBytes: config.RecoveryMaxCanonicalBytes,
		MaxEncodedBytes:   config.RecoveryMaxEncodedBytes,
		MaxMembers:        config.RecoveryMaxMembers,
	}
	if err := transportrecovery.WriteDecision(writer, decision); err != nil {
		return RecoveryReceiveResult{}, fmt.Errorf("write FI recovery decision: %w", err)
	}

	custody, err := transportrecovery.ReceiveToDurableCustody(
		reader,
		transportrecovery.CustodyConfig{
			BatchCRL:          config.BatchCRL,
			BatchIssuer:       config.BatchIssuer,
			CurrentTime:       currentTime,
			MaxCanonicalBytes: config.RecoveryMaxCanonicalBytes,
			MaxEncodedBytes:   config.RecoveryMaxEncodedBytes,
			MaxMembers:        config.RecoveryMaxMembers,
			Root:              config.Root,
			RootDir:           config.CustodyRoot,
			Source:            config.Source,
		},
	)
	if err != nil {
		return RecoveryReceiveResult{Offer: offer}, fmt.Errorf("receive FI recovery to durable custody: %w", err)
	}
	ack, err := transportrecovery.AcknowledgementFromCustody(custody)
	if err != nil {
		return RecoveryReceiveResult{Offer: offer, Custody: custody}, err
	}
	if err := transportrecovery.WriteAcknowledgement(writer, ack); err != nil {
		return RecoveryReceiveResult{Offer: offer, Custody: custody}, fmt.Errorf("write FI durable recovery acknowledgement: %w", err)
	}
	return RecoveryReceiveResult{Offer: offer, Custody: custody, Acknowledgement: ack}, nil
}

func validateRecoveryConfig(config Config) error {
	allZero := config.RecoveryMaxCanonicalBytes == 0 && config.RecoveryMaxEncodedBytes == 0 && config.RecoveryMaxMembers == 0
	if allZero {
		return nil
	}
	if config.RecoveryMaxCanonicalBytes == 0 || config.RecoveryMaxEncodedBytes == 0 || config.RecoveryMaxMembers < 2 {
		return errors.New("FI recovery limits must all be enabled together")
	}
	if config.RecoveryMaxCanonicalBytes > uint64(1<<63-1) || config.RecoveryMaxEncodedBytes > uint64(1<<63-1) || config.RecoveryMaxMembers > 1_000_000 {
		return errors.New("FI recovery limits exceed structural safety bounds")
	}
	return nil
}
