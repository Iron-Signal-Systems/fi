// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package transportreceiver

import (
	"context"
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
	DeferredDisabled   uint64
	Discovered         uint64
	ReadyPublished     uint64
	ReadyWarning       string
	ReadyWarnings      uint64
	RecordedNew        uint64
	RemovedProvisional uint64
}

// RecoverGenerationStartup retains the historical API used by existing callers.
// The service uses RecoverGenerationStartupWithContext so SIGTERM can cancel
// both the outer byte stream and the slower missing-receipt semantic recovery.
//
// A failure leaves the receiver unopened. Previously durable custody is retained
// for operator inspection/retry. No success acknowledgement can be emitted from
// this startup path because no authenticated sender transaction is present.
func RecoverGenerationStartup(
	config Config,
	currentTime time.Time,
) (GenerationStartupResult, error) {
	return RecoverGenerationStartupWithContext(
		context.Background(), config, currentTime, nil,
	)
}

// RecoverGenerationStartupWithContext first checks each existing immutable
// recorded receipt against its exact FIGT transfer and current signing trust.
// An exact receipt match requires only bounded streaming of compressed bytes:
// never decompression or semantic replay. Absent receipts continue through the
// original full semantic recording path. Corrupt or conflicting receipts fail
// closed. Recovery remains a prerequisite to listener startup.
// Progress is reported every 128 objects and on completion.
func RecoverGenerationStartupWithContext(
	ctx context.Context,
	config Config,
	currentTime time.Time,
	onProgress func(GenerationStartupResult),
) (GenerationStartupResult, error) {
	if ctx == nil {
		return GenerationStartupResult{}, errors.New(
			"FI receiver startup recovery context is required",
		)
	}
	if err := ctx.Err(); err != nil {
		return GenerationStartupResult{}, err
	}
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

	validationConfig := transactionConfig

	if validationConfig.Custody.Receive.Source.SourceID == "" &&
		config.LookupSource != nil {
		validationConfig.Custody.Receive.Source.SourceID =
			"registry-startup-validation"
	}

	if err := validateGenerationReceiveConfig(
		validationConfig,
	); err != nil {
		return GenerationStartupResult{}, fmt.Errorf(
			"validate FI generation startup receiver boundary: %w",
			err,
		)
	}

	recovery, err := transportgeneration.RecoverDurableCustodyRoot(
		validationConfig.Custody,
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
		if err := ctx.Err(); err != nil {
			return result, fmt.Errorf("cancel FI generation startup recovery: %w", err)
		}
		objectConfig := transactionConfig

		if config.LookupSource != nil {
			descriptor, err :=
				transportgeneration.ReadDiscoveredCustodyDescriptor(
					discovered,
					config.GenerationCustodyRoot,
				)
			if err != nil {
				return result, fmt.Errorf(
					"inspect restart-discovered FI generation custody %q: %w",
					discovered.Path,
					err,
				)
			}

			source, found, err := resolveSourceID(
				config,
				descriptor.SourceID,
			)
			if err != nil {
				return result, fmt.Errorf(
					"resolve restart-discovered FI generation source %q: %w",
					descriptor.SourceID,
					err,
				)
			}

			if !found {
				return result, fmt.Errorf(
					"restart-discovered FI generation source %q is not enrolled",
					descriptor.SourceID,
				)
			}

			objectConfig.Custody.Receive.Source = source

			// A retired source may have immutable custody from its active
			// enrollment period. Keep it intact, but do not process it
			// under current signing authorization or generate new receipts
			// and READY hints. Deferred objects require offline review.
			if !source.Enabled {
				result.DeferredDisabled++
				if onProgress != nil {
					done := result.AlreadyRecorded + result.RecordedNew + result.DeferredDisabled
					if done%128 == 0 || done == result.Discovered {
						onProgress(result)
					}
				}
				continue
			}
		}

		if err := validateGenerationReceiveConfig(
			objectConfig,
		); err != nil {
			return result, fmt.Errorf(
				"validate restart-discovered FI generation source boundary: %w",
				err,
			)
		}

		// Read the already-published receipt before entering the original
		// decompression and semantic gate. Presence alone is not proof:
		// the complete outer FIGT SHA-256, signed metadata, current source
		// authorization and receipt fields must all match.
		recorded, found, err := generationrecorder.VerifyPreviouslyRecordedCustody(
			ctx, discovered, objectConfig.Custody, objectConfig.Recorder,
		)
		if err != nil {
			return result, fmt.Errorf(
				"verify previously recorded FI generation custody %q: %w",
				discovered.Path, err,
			)
		}
		if !found {
			// No receipt yet: preserve exact original full verification and
			// durable receipt publication. This path also accepts cancellation.
			recorded, err = generationrecorder.RecordDiscoveredCustodyDurablyContext(
				ctx, discovered, objectConfig.Custody, objectConfig.Recorder,
			)
			if err != nil {
				return result, fmt.Errorf(
					"record restart-discovered FI generation custody %q: %w",
					discovered.Path, err,
				)
			}
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
		if onProgress != nil {
			done := result.AlreadyRecorded + result.RecordedNew + result.DeferredDisabled
			if done%128 == 0 || done == result.Discovered {
				onProgress(result)
			}
		}
	}

	return result, nil
}
