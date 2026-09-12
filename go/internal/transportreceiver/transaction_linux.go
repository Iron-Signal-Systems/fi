// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportreceiver

import (
	"errors"
	"fmt"
	"io"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportack"
)

// ReceiveTransactionResult captures the durable custody facts and the exact
// success acknowledgement derived from them.
//
// If acknowledgement transmission fails after custody succeeds, the result is
// still returned with the durable custody and acknowledgement populated. The
// source must retry because it did not receive a complete acknowledgement; an
// exact retry will then classify as DUPLICATE and can be acknowledged again.
type ReceiveTransactionResult struct {
	Acknowledgement transportack.Acknowledgement
	Custody         DurableCustodyResult
}

// ReceiveAndAcknowledge performs one receiver-side FI transport transaction.
// It first establishes durable receiver custody and only then writes the success
// acknowledgement derived from that custody result.
//
// Validation failure, storage failure, and custody conflict return without
// writing any success acknowledgement. Once custody succeeds, a later
// acknowledgement write failure does not undo or remove durable custody.
func ReceiveAndAcknowledge(
	reader io.Reader,
	acknowledgementWriter io.Writer,
	config CustodyConfig,
) (ReceiveTransactionResult, error) {
	if reader == nil {
		return ReceiveTransactionResult{}, errors.New("batch reader is required")
	}
	if acknowledgementWriter == nil {
		return ReceiveTransactionResult{}, errors.New(
			"acknowledgement writer is required",
		)
	}

	custody, err := ReceiveToDurableCustody(reader, config)
	if err != nil {
		return ReceiveTransactionResult{}, fmt.Errorf(
			"establish FI durable receiver custody: %w",
			err,
		)
	}

	acknowledgement, err := acknowledgementFromCustody(custody)
	if err != nil {
		return ReceiveTransactionResult{Custody: custody}, fmt.Errorf(
			"construct FI durable acknowledgement: %w",
			err,
		)
	}

	result := ReceiveTransactionResult{
		Acknowledgement: acknowledgement,
		Custody:         custody,
	}
	if err := transportack.WriteAcknowledgement(
		acknowledgementWriter,
		acknowledgement,
	); err != nil {
		return result, fmt.Errorf(
			"write FI durable acknowledgement: %w",
			err,
		)
	}

	return result, nil
}

func acknowledgementFromCustody(
	custody DurableCustodyResult,
) (transportack.Acknowledgement, error) {
	var outcome transportack.Outcome
	switch custody.Disposition {
	case CustodyDispositionDuplicate:
		outcome = transportack.OutcomeDurableDuplicate
	case CustodyDispositionNew:
		outcome = transportack.OutcomeDurableNew
	default:
		return transportack.Acknowledgement{}, fmt.Errorf(
			"unsupported FI custody disposition %q",
			custody.Disposition,
		)
	}

	return transportack.NewDurableAcknowledgement(
		outcome,
		custody.SourceID,
		custody.BatchID,
		custody.DataBytes,
		custody.DataSHA256,
		custody.ManifestSHA256,
		custody.FrameBytes,
		custody.FrameSHA256,
	)
}
