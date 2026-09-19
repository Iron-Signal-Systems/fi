// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package generationrecorder

import (
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

// RecordCustodyDurably reopens one exact durable FIGT custody object, revalidates
// its transport identity and current signing trust while streaming canonical
// artifacts through the collector semantic gate, then publishes the immutable
// recorder receipt.
//
// This function deliberately does not write a generation protocol
// acknowledgement and does not retire sender-side state.
func RecordCustodyDurably(
	custody transportgeneration.CustodyResult,
	custodyConfig transportgeneration.CustodyConfig,
	recorderConfig DurableConfig,
) (
	DurableResult,
	error,
) {
	if err := validateDurableConfig(recorderConfig); err != nil {
		return DurableResult{}, err
	}

	state, err := newValidator(
		custody.Transfer.Descriptor,
		recorderConfig.Semantic,
	)
	if err != nil {
		return DurableResult{}, err
	}

	transfer, err := transportgeneration.ReadDurableCustodyArtifacts(
		custody,
		custodyConfig,
		state.consumeArtifact,
	)
	if err != nil {
		return DurableResult{}, fmt.Errorf(
			"read FI generation durable custody for recorder: %w",
			err,
		)
	}

	semantic, err := state.result(
		transfer.Descriptor,
		transfer.Descriptor.SourceBytes,
	)
	if err != nil {
		return DurableResult{}, err
	}

	return publishRecordedSemanticResult(
		transfer,
		semantic,
		recorderConfig,
	)
}
