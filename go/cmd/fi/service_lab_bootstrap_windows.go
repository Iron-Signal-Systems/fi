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
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/checkpoint"
	"golang.org/x/sys/windows/svc"
)

// The FIUSNReader broker authenticates the FICollector service SID, not merely
// the account name. Bootstrap therefore runs only inside the FICollector SCM
// process. It never weakens broker authorization or synthesizes a checkpoint.
const labBootstrapEnv = "FI_USN_PIPELINE_LAB_BOOTSTRAP"

func labBootstrapRequested() (bool, error) {
	switch strings.TrimSpace(os.Getenv(labBootstrapEnv)) {
	case "":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be unset or exactly 1", labBootstrapEnv)
	}
}

func bootstrapConfiguredRoots(ctx context.Context, snapshot serviceOperationalSnapshot) error {
	if len(snapshot.GovernedRoots) != 1 {
		return errors.New("lab bootstrap requires exactly one configured canary root")
	}
	if !filepath.IsAbs(snapshot.StateDir) ||
		!strings.EqualFold(filepath.Clean(os.Getenv("FI_STATE_DIR")), filepath.Clean(snapshot.StateDir)) {
		return errors.New("lab bootstrap FI_STATE_DIR must equal configured storage.state_dir")
	}
	configured, _, err := config.LoadDefault()
	if err != nil {
		return err
	}
	if !filepath.IsAbs(configured.Storage.SpoolDir) ||
		!strings.EqualFold(filepath.Clean(os.Getenv("FI_SPOOL_DIR")), filepath.Clean(configured.Storage.SpoolDir)) {
		return errors.New("lab bootstrap FI_SPOOL_DIR must equal configured storage.spool_dir")
	}
	// Exact root acceptance is enforced by both writeConfiguredRoot and
	// runUSNPipelineLabInit. A previously created queue prohibits any legacy
	// collection. A failed bootstrap is preserved for explicit review.
	root := snapshot.GovernedRoots[0]
	if err := guardLegacyUSNRoot(root); err != nil {
		return err
	}
	if err := recoverServiceSpoolPublications(); err != nil {
		return err
	}
	result, err := writeConfiguredRoot(ctx, root)
	if err != nil {
		return fmt.Errorf("baseline/catch-up %s: %w", root, err)
	}
	if result.Status == configuredStatusPartial || result.Status == configuredStatusFailed {
		return fmt.Errorf("baseline/catch-up %s did not complete: %s", root, result.Status)
	}
	statePath, err := checkpoint.DefaultPath(configuredScopeID(root))
	if err != nil {
		return err
	}
	assessment, err := checkpoint.Check(ctx, configuredScopeID(root), root, statePath)
	if err != nil {
		return fmt.Errorf("post-baseline continuity verification %s: %w", root, err)
	}
	if assessment.Status != checkpoint.ContinuityContinuous {
		return fmt.Errorf("post-baseline continuity gap %s: %s", root, assessment.ReasonCode)
	}
	if err := runUSNPipelineLabInit(ctx, root); err != nil {
		return fmt.Errorf("initialize lab queue %s: %w", root, err)
	}
	return nil
}

func (service *fiWindowsService) executeLabBootstrap(
	requests <-chan svc.ChangeRequest,
	statuses chan<- svc.Status,
) (bool, uint32) {
	statuses <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	running := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	statuses <- running
	go func() { done <- bootstrapConfiguredRoots(ctx, service.operationalSnapshot) }()

	finalize := func(err error) (bool, uint32) {
		outcome := serviceOutcomeComplete
		detail := ""
		if err != nil {
			outcome = serviceOutcomeFailed
			detail = err.Error()
		}
		recordErr := appendServiceRuntimeRecordAt(service.operationalSnapshot.StateDir,
			serviceRuntimeRecord{
				Version:         serviceRuntimeVersion,
				RecordKind:      "USNPipelineLabBootstrap",
				ObservedAt:      serviceNow(),
				Outcome:         outcome,
				ConfiguredRoots: len(service.operationalSnapshot.GovernedRoots),
				Error:           detail,
			})
		statuses <- svc.Status{State: svc.StopPending}
		if err != nil || recordErr != nil {
			return false, 1
		}
		return false, 0
	}
	for {
		select {
		case err := <-done:
			return finalize(err)
		case change, ok := <-requests:
			if !ok {
				cancel()
				err := <-done
				if err == nil {
					err = context.Canceled
				}
				return finalize(err)
			}
			switch change.Cmd {
			case svc.Interrogate:
				statuses <- running
			case svc.Stop, svc.Shutdown:
				cancel()
				err := <-done
				if err == nil {
					err = context.Canceled
				}
				return finalize(err)
			}
		}
	}
}
