// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package generationrecorder

import (
	"errors"
	"fmt"
	"io"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

// RecordDiscoveredCustodyDurably processes one custody object returned by
// transportgeneration restart recovery.
//
// The custody payload is streamed once through transport validation and the
// collector semantic recorder gate. Only then may the immutable recorded
// receipt be published. The durable FIGT custody object is retained.
//
// This function deliberately does not transmit a generation acknowledgement or
// retire sender-side state.
func RecordDiscoveredCustodyDurably(
	discovered transportgeneration.DiscoveredCustody,
	custodyConfig transportgeneration.CustodyConfig,
	recorderConfig DurableConfig,
) (
	DurableResult,
	error,
) {
	if err := validateDurableConfig(recorderConfig); err != nil {
		return DurableResult{}, err
	}

	cache, err := newReceiverVerifiedBatchWriter(recorderConfig.VerifiedBatchRoot)
	if err != nil { return DurableResult{}, err }
	if cache != nil { defer cache.Discard() }
	var state *validator

	custody, err := transportgeneration.ReadDiscoveredDurableCustodyArtifacts(
		discovered,
		custodyConfig,
		func(
			descriptor transportgeneration.Descriptor,
		) (
			transportgeneration.CanonicalArtifactHandler,
			error,
		) {
			if state != nil {
				return nil, errors.New(
					"FI generation restart recorder validator was initialized more than once",
				)
			}

			created, err := newValidator(
				descriptor,
				recorderConfig.Semantic,
			)
			if err != nil {
				return nil, err
			}

			state = created
			if cache == nil { return state.consumeArtifact, nil }
			return func(name string, reader io.Reader) error {
				return cache.Consume(name, reader, state.consumeArtifact)
			}, nil
		},
	)
	if err != nil {
		return DurableResult{}, fmt.Errorf(
			"read restart-discovered FI generation custody for recorder: %w",
			err,
		)
	}

	if state == nil {
		return DurableResult{}, errors.New(
			"FI generation restart recorder validator was not initialized",
		)
	}

	semantic, err := state.result(
		custody.Transfer.Descriptor,
		custody.Transfer.Descriptor.SourceBytes,
	)
	if err != nil {
		return DurableResult{}, err
	}

	recorded, err := publishRecordedSemanticResult(
		custody.Transfer,
		semantic,
		recorderConfig,
	)
	if err != nil { return DurableResult{}, err }
	if cache != nil {
		if err := cache.Publish(recorded); err != nil {
			return DurableResult{}, fmt.Errorf("publish receiver-authenticated restart cache: %w",err)
		}
	}
	return recorded, nil

}
