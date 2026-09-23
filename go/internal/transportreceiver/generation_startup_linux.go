// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package transportreceiver

import (
	"errors"
	"fmt"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
	"github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
)

// GenerationStartupResult describes one fail-closed receiver startup pass over
// durable generation custody.
//
// Startup recovery may create immutable recorder receipts for custody that was
// durable before a prior receiver interruption. Newly created receipts also get
// a best-effort non-authoritative ingest-ready hint. It never emits a protocol
// ACK and never removes the durable FIGT custody object.
type GenerationStartupResult struct {
	AlreadyRecorded    uint64
	Discovered         uint64
	ReadyPublished     uint64
	ReadyWarning       string
	ReadyWarnings      uint64
	RecordedNew        uint64
	RemovedProvisional uint64
}

// RecoverGenerationStartup validates generation runtime configuration, recovers
// the durable generation custody directory, and drives every discovered FIGT
// object through current transport trust plus collector semantic recording
// before the listener is allowed to accept another connection.
//
// A failure leaves the receiver unopened. Previously durable custody is retained
// for operator inspection/retry. No success acknowledgement can be emitted from
// this startup path because no authenticated sender transaction is present.
func RecoverGenerationStartup(
	config Config,
	currentTime time.Time,
) (
	GenerationStartupResult,
	error,
) {
	if currentTime.IsZero() {
		return GenerationStartupResult{}, errors.New(
			"FI generation startup current time is required",
		)
	}

	if err := validateGenerationListenerConfig(config); err != nil {
		return GenerationStartupResult{}, fmt.Errorf(
			"validate FI generation startup configuration: %w",
			err,
		)
	}

	if !generationListenerEnabled(config) {
		return GenerationStartupResult{}, nil
	}

	transactionConfig := generationReceiveConfigFromListener(
		config,
		currentTime,
	)

	if err := validateGenerationReceiveConfig(transactionConfig); err != nil {
		return GenerationStartupResult{}, fmt.Errorf(
			"validate FI generation startup receiver boundary: %w",
			err,
		)
	}

	recovery, err := transportgeneration.RecoverDurableCustodyRoot(
		transactionConfig.Custody,
	)
	if err != nil {
		return GenerationStartupResult{}, fmt.Errorf(
			"recover FI generation durable custody at startup: %w",
			err,
		)
	}

	result := GenerationStartupResult{
		Discovered:         uint64(len(recovery.Objects)),
		RemovedProvisional: recovery.RemovedProvisional,
	}

	for _, discovered := range recovery.Objects {
		recorded, err :=
			generationrecorder.RecordDiscoveredCustodyDurably(
				discovered,
				transactionConfig.Custody,
				transactionConfig.Recorder,
			)
		if err != nil {
			return result, fmt.Errorf(
				"record restart-discovered FI generation custody %q: %w",
				discovered.Path,
				err,
			)
		}

		switch recorded.Disposition {
		case generationrecorder.RecordedDispositionNew:
			result.RecordedNew++

			_, warning := publishGenerationReady(
				transactionConfig.ReadyRoot,
				recorded,
			)
			if warning != "" {
				result.ReadyWarnings++
				if result.ReadyWarning == "" {
					result.ReadyWarning = warning
				}
			} else {
				result.ReadyPublished++
			}

		case generationrecorder.RecordedDispositionAlreadyRecorded:
			result.AlreadyRecorded++

		default:
			return result, fmt.Errorf(
				"unsupported FI generation startup recorder disposition %q",
				recorded.Disposition,
			)
		}
	}

	return result, nil
}
