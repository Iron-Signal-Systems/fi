// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

// writeServiceRootCollector is the service-mode current-state/root lane.
// Windows Security has its own independently scheduled worker and therefore is
// intentionally not prepared or finished here.
func writeServiceRootCollector(
	ctx context.Context,
) (configuredRunSummary, error) {
	value, configPath, err := config.LoadDefault()
	if err != nil {
		return configuredRunSummary{}, err
	}

	summary := configuredRunSummary{
		ConfigPath:      configPath,
		VersionID:       value.VersionID,
		ConfiguredRoots: len(value.GovernedRoots),
		Complete:        true,
		Roots:           make([]configuredRootSummary, 0, len(value.GovernedRoots)),
		Semantics: "FI service mode collects governed-root current state independently from the Windows Security Event Log stream. " +
			"Root checkpoint ownership remains serialized per governed root while Windows Security owns only its Security-channel checkpoint.",
	}

	spoolDir, err := spool.DefaultDir()
	if err != nil {
		summary.Complete = false
		return summary, err
	}

	boundary, boundaryErr := spool.AcquirePublishBoundary()
	if boundaryErr != nil {
		summary.Complete = false
		return summary, fmt.Errorf(
			"acquire FI spool publish boundary for interrupted recovery: %w",
			boundaryErr,
		)
	}

	spoolRecovery, recoveryErr := spool.PreserveInterruptedArtifacts(spoolDir)
	recoveryErr = errors.Join(recoveryErr, boundary.Close())
	summary.SpoolRecovery = spoolRecovery
	if recoveryErr != nil {
		summary.Complete = false
		return summary, fmt.Errorf(
			"preserve interrupted spool artifacts: %w",
			recoveryErr,
		)
	}

	var runErr error

	for _, governedRoot := range value.GovernedRoots {
		if err := ctx.Err(); err != nil {
			summary.Complete = false
			runErr = errors.Join(runErr, err)
			break
		}

		scopeID := configuredScopeID(governedRoot)
		rootLock := serviceRootLocks.lockFor(scopeID)

		rootLock.Lock()
		rootSummary, rootErr := writeConfiguredRoot(ctx, governedRoot)
		rootLock.Unlock()

		if rootErr != nil {
			rootSummary.Status = configuredStatusFailed
			rootSummary.Error = rootErr.Error()
			summary.FailedRoots++
			summary.Complete = false
			runErr = errors.Join(
				runErr,
				fmt.Errorf(
					"configured root %q: %w",
					governedRoot,
					rootErr,
				),
			)
		} else {
			switch rootSummary.Status {
			case configuredStatusPartial:
				summary.PartialRoots++
				summary.Complete = false
			default:
				rootSummary.Status = configuredStatusComplete
				summary.CompletedRoots++
			}
		}

		summary.Roots = append(summary.Roots, rootSummary)
	}

	return summary, runErr
}
