// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/transportsender"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/certstore"
)

const generationStageDirectoryName = "generations"

// runGenerationQueue runs three independent pipelines: active-spool rollover,
// semantic-free local generation sealing, and generation transport. Rollover
// never waits for a build, and neither local pipeline opens a receiver
// connection.
func runGenerationQueue(ctx context.Context, config senderConfig) error {
	if ctx == nil {
		return errors.New("context is required")
	}

	stageRoot := filepath.Join(config.StageDir, generationStageDirectoryName)
	if err := ensureGenerationStageRoot(stageRoot); err != nil {
		return err
	}
	if err := reclaimGenerationRetirementTombstones(config, stageRoot); err != nil {
		return err
	}

	rawRoot, err := transportsender.EnsureGenerationRawRoot(config.SpoolDir)
	if err != nil {
		return fmt.Errorf("open FI raw-generation queue: %w", err)
	}

	if err := transportsender.RecoverTransportGenerationBuilds(
		rawRoot,
		stageRoot,
		config.SourceID,
		config.GenerationMaxEncodedBytes,
	); err != nil {
		return fmt.Errorf("recover FI transport-generation build state: %w", err)
	}

	localErrors := make(chan error, 2)
	go runGenerationRollover(ctx, config, localErrors)
	go runGenerationBuilder(ctx, config, rawRoot, stageRoot, localErrors)

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-localErrors:
			if err != nil {
				return err
			}
		default:
		}

		generation, found, err := transportsender.NextTransportGeneration(
			stageRoot,
			config.SourceID,
		)
		if err != nil {
			return fmt.Errorf("inspect FI transport-generation queue: %w", err)
		}
		if !found {
			if err := waitForGenerationActivity(ctx, config.PollInterval, localErrors); err != nil {
				if errors.Is(err, context.Canceled) {
					return nil
				}
				return err
			}
			continue
		}

		attemptContext, cancel := context.WithTimeout(
			ctx,
			config.GenerationTransferTimeout,
		)
		err = sendTransportGeneration(attemptContext, config, generation)
		cancel()
		if err == nil {
			if err := reclaimGenerationRetirementTombstones(config, stageRoot); err != nil {
				return err
			}
			continue
		}
		if ctx.Err() != nil {
			return nil
		}
		if !errors.Is(err, transportsender.ErrRetryableTransport) {
			return fmt.Errorf("FI generation transport fail-stopped: %w", err)
		}

		fmt.Fprintf(
			os.Stderr,
			"ERROR: FI generation transport failed: %v\n",
			err,
		)

		if err := waitForGenerationActivity(ctx, config.RetryBackoff, localErrors); err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
	}
}

func reclaimGenerationRetirementTombstones(
	config senderConfig,
	stageRoot string,
) error {
	result, err := transportsender.ReclaimGenerationRetirementTombstones(
		stageRoot,
		config.SourceID,
	)
	if err != nil {
		return fmt.Errorf(
			"reclaim FI generation retirement tombstones: %w",
			err,
		)
	}

	if result.Reclaimed != 0 || result.Resumed != 0 {
		fmt.Printf("GenerationReclaimed:%d\n", result.Reclaimed)
		fmt.Printf("GenerationReclaimResumed:%d\n", result.Resumed)
		fmt.Printf("GenerationReclaimedBytes:%d\n", result.ReclaimedDiskBytes)
	}

	return nil
}

func runGenerationBuilder(
	ctx context.Context,
	config senderConfig,
	rawRoot string,
	stageRoot string,
	errorsOut chan<- error,
) {
	for {
		if ctx.Err() != nil {
			return
		}

		raw, found, err := transportsender.NextRawGeneration(rawRoot)
		if err != nil {
			sendGenerationError(
				ctx,
				errorsOut,
				fmt.Errorf("inspect FI raw-generation queue: %w", err),
			)
			return
		}
		if !found {
			if !waitGenerationWorker(ctx, config.PollInterval) {
				return
			}
			continue
		}

		identity, err := certstore.LoadLocalMachineSigningIdentity(
			config.BatchSigningCertificateSHA256,
		)
		if err != nil {
			sendGenerationError(
				ctx,
				errorsOut,
				fmt.Errorf("load FI batch-signing identity for generation build: %w", err),
			)
			return
		}

		generation, buildErr := transportsender.BuildRawTransportGeneration(
			ctx,
			transportsender.GenerationSealConfig{
				BatchSigner:             identity.Signer,
				BatchSigningCertificate: identity.Certificate,
				MaxEncodedBytes:         config.GenerationMaxEncodedBytes,
				SourceID:                config.SourceID,
				SpoolDir:                config.SpoolDir,
				StageRoot:               stageRoot,
			},
			raw,
		)

		closeErr := identity.Close()
		if buildErr != nil {
			sendGenerationError(
				ctx,
				errorsOut,
				fmt.Errorf("FI generation builder fail-stopped: %w", buildErr),
			)
			return
		}
		if closeErr != nil {
			sendGenerationError(
				ctx,
				errorsOut,
				fmt.Errorf("close FI generation signing identity: %w", closeErr),
			)
			return
		}

		descriptor := generation.Published.Signed.Descriptor

		fmt.Printf("Generation:     SEALED\n")
		fmt.Printf("GenerationID:   %s\n", generation.GenerationID)
		fmt.Printf("GenerationArtifacts:%d\n", descriptor.ArtifactCount)
		fmt.Printf(
			"GenerationBytes:%d source / %d canonical / %d encoded\n",
			descriptor.SourceBytes,
			descriptor.CanonicalBytes,
			descriptor.EncodedDataBytes,
		)
	}
}

func runGenerationRollover(
	ctx context.Context,
	config senderConfig,
	errorsOut chan<- error,
) {
	roll := func() bool {
		raw, found, err := transportsender.RolloverPublishedSpool(config.SpoolDir)
		if err != nil {
			sendGenerationError(
				ctx,
				errorsOut,
				fmt.Errorf("FI generation rollover fail-stopped: %w", err),
			)
			return false
		}
		if found {
			fmt.Printf("Generation:     ROLLED\n")
			fmt.Printf("GenerationID:   %s\n", raw.GenerationID)
			fmt.Printf("GenerationRaw:  %s\n", raw.GenerationDir)
		}
		return true
	}

	// Startup immediately freezes any pre-existing backlog. The active spool is
	// replaced before sealing begins, so the collector resumes against an empty
	// path while the builder works on the immutable old directory.
	if !roll() {
		return
	}

	ticker := time.NewTicker(config.GenerationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !roll() {
				return
			}
		}
	}
}

func sendTransportGeneration(
	ctx context.Context,
	config senderConfig,
	generation transportsender.TransportGeneration,
) error {
	if ctx == nil {
		return errors.New("context is required")
	}

	// Transport starts here. The generation already exists as a complete durable
	// semantic-free object in the active transport queue. No build or compression
	// time consumes this deadline.
	connection, closeTransport, err := dialAuthenticatedSenderTransport(ctx, config)
	if err != nil {
		return err
	}
	defer closeTransport()

	descriptor := generation.Published.Signed.Descriptor

	fmt.Printf("Generation:     SENDING\n")
	fmt.Printf("GenerationID:   %s\n", generation.GenerationID)
	fmt.Printf("GenerationArtifacts:%d\n", descriptor.ArtifactCount)
	fmt.Printf(
		"GenerationBytes:%d source / %d canonical / %d encoded\n",
		descriptor.SourceBytes,
		descriptor.CanonicalBytes,
		descriptor.EncodedDataBytes,
	)

	transaction, err := transportsender.SendAndRetireTransportGeneration(
		connection,
		generation,
	)
	if err != nil {
		return err
	}

	fmt.Printf("Generation:     ACKNOWLEDGED\n")
	fmt.Printf("GenerationID:   %s\n", generation.GenerationID)
	fmt.Printf("Acknowledged:   %s\n", transaction.Acknowledgement.Outcome)
	fmt.Printf("Retirement:     %s\n", transaction.Retirement.Disposition)

	return nil
}

func ensureGenerationStageRoot(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create FI generation stage root: %w", err)
	}

	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect FI generation stage root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("FI generation stage root must be a real directory")
	}

	return nil
}

func sendGenerationError(
	ctx context.Context,
	destination chan<- error,
	err error,
) {
	select {
	case destination <- err:
	case <-ctx.Done():
	}
}

func waitForGenerationActivity(
	ctx context.Context,
	delay time.Duration,
	errorsIn <-chan error,
) error {
	if delay <= 0 {
		return errors.New("FI generation wait interval must be greater than zero")
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return context.Canceled
	case err := <-errorsIn:
		if err != nil {
			return err
		}
		return nil
	case <-timer.C:
		return nil
	}
}

func waitGenerationWorker(
	ctx context.Context,
	delay time.Duration,
) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
