// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/checkpoint"
)

type configuredRootAction string

type configuredRootStatus string

const (
	configuredActionBaselineAndCatchUp configuredRootAction = "BaselineAndCatchUp"
	configuredActionUSNCatchUp         configuredRootAction = "USNCatchUp"

	configuredStatusComplete configuredRootStatus = "Complete"
	configuredStatusFailed   configuredRootStatus = "Failed"
)

type configuredRootSummary struct {
	GovernedRoot    string                    `json:"governed_root"`
	ScopeID         string                    `json:"scope_id"`
	StatePath       string                    `json:"state_path"`
	CheckpointFound bool                      `json:"checkpoint_found"`
	Action          configuredRootAction      `json:"action"`
	Status          configuredRootStatus      `json:"status"`
	TargetUSN       string                    `json:"target_usn,omitempty"`
	Baseline        *baselineSpoolSummary     `json:"baseline,omitempty"`
	USNPasses       []usnSpoolNextSummary     `json:"usn_passes"`
	FinalCheckpoint *checkpoint.USNCheckpoint `json:"final_checkpoint,omitempty"`
	Error           string                    `json:"error,omitempty"`
}

type configuredRunSummary struct {
	ConfigPath                       string                    `json:"config_path"`
	VersionID                        string                    `json:"version_id"`
	ConfiguredRoots                  int                       `json:"configured_roots"`
	CompletedRoots                   int                       `json:"completed_roots"`
	FailedRoots                      int                       `json:"failed_roots"`
	Complete                         bool                      `json:"complete"`
	MonitoringPrerequisitesSatisfied bool                      `json:"monitoring_prerequisites_satisfied"`
	WindowsSecurity                  configuredSecuritySummary `json:"windows_security"`
	Roots                            []configuredRootSummary   `json:"roots"`
	Semantics                        string                    `json:"semantics"`
}

func runConfiguredCollector() {
	summary, err := writeConfiguredCollector(context.Background())
	writeIndentedJSON(summary)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func writeConfiguredCollector(ctx context.Context) (configuredRunSummary, error) {
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
		Semantics:       "FI processes Windows Security activity and each configured governed root as independent source observations. Missing root checkpoints start safe baselines; continuous root checkpoints catch up USN. Windows Security is anchored before root processing and caught up afterward. Monitoring coverage is reported explicitly and is not inferred from absent events.",
	}

	var runErr error
	securityPrepared, securityPrepareErr := prepareConfiguredSecurity()
	if securityPrepareErr != nil {
		securityPrepared.Summary.Status = configuredSecurityFailed
		securityPrepared.Summary.Error = securityPrepareErr.Error()
		summary.WindowsSecurity = securityPrepared.Summary
		summary.Complete = false
		runErr = errors.Join(runErr, fmt.Errorf("Windows Security source: %w", securityPrepareErr))
	}
	for _, governedRoot := range value.GovernedRoots {
		if err := ctx.Err(); err != nil {
			summary.Complete = false
			runErr = errors.Join(runErr, err)
			break
		}

		rootSummary, rootErr := writeConfiguredRoot(ctx, governedRoot)
		if rootErr != nil {
			rootSummary.Status = configuredStatusFailed
			rootSummary.Error = rootErr.Error()
			summary.FailedRoots++
			summary.Complete = false
			runErr = errors.Join(runErr, fmt.Errorf("configured root %q: %w", governedRoot, rootErr))
		} else {
			rootSummary.Status = configuredStatusComplete
			summary.CompletedRoots++
		}
		summary.Roots = append(summary.Roots, rootSummary)
	}

	if securityPrepareErr == nil {
		securitySummary, securityErr := finishConfiguredSecurity(ctx, securityPrepared, configuredSecurityScopes(value.GovernedRoots))
		if securityErr != nil {
			securitySummary.Status = configuredSecurityFailed
			securitySummary.Error = securityErr.Error()
			summary.Complete = false
			runErr = errors.Join(runErr, fmt.Errorf("Windows Security source: %w", securityErr))
		}
		summary.WindowsSecurity = securitySummary
		if securitySummary.Coverage != nil && securitySummary.Coverage.Status == "Ready" {
			summary.MonitoringPrerequisitesSatisfied = true
		}
	}

	return summary, runErr
}

func writeConfiguredRoot(ctx context.Context, governedRoot string) (configuredRootSummary, error) {
	scopeID := configuredScopeID(governedRoot)
	statePath, err := checkpoint.DefaultPath(scopeID)
	if err != nil {
		return configuredRootSummary{GovernedRoot: governedRoot, ScopeID: scopeID}, err
	}

	summary := configuredRootSummary{
		GovernedRoot: governedRoot,
		ScopeID:      scopeID,
		StatePath:    statePath,
		USNPasses:    []usnSpoolNextSummary{},
	}

	checkpointFound, err := fileExists(statePath)
	if err != nil {
		return summary, err
	}
	summary.CheckpointFound = checkpointFound

	switch checkpointFound {
	case false:
		summary.Action = configuredActionBaselineAndCatchUp
		baseline, err := writeBaselineSpoolRoot(ctx, scopeID, governedRoot)
		summary.Baseline = &baseline
		if err != nil {
			return summary, err
		}
		if baseline.PostBaselineAssessment == nil || baseline.Checkpoint == nil {
			return summary, errors.New("successful baseline did not return checkpoint continuity state")
		}

		// Catch up only through the journal position observed at the post-baseline
		// acceptance boundary. FI may create newer USNs while persisting its own
		// state and spool output; this fixed target prevents a configured run from
		// chasing its own writes indefinitely.
		summary.TargetUSN = baseline.PostBaselineAssessment.JournalState.NextUSN
		passes, finalCheckpoint, err := catchUpConfiguredRoot(
			ctx,
			scopeID,
			governedRoot,
			summary.TargetUSN,
		)
		summary.USNPasses = passes
		summary.FinalCheckpoint = finalCheckpoint
		if err != nil {
			return summary, err
		}
		return summary, nil

	case true:
		summary.Action = configuredActionUSNCatchUp
		assessment, err := checkpoint.Check(ctx, scopeID, governedRoot, statePath)
		if err != nil {
			return summary, err
		}
		if assessment.Status != checkpoint.ContinuityContinuous {
			return summary, fmt.Errorf("existing checkpoint is not continuous: %s", assessment.ReasonCode)
		}

		summary.TargetUSN = assessment.JournalState.NextUSN
		passes, finalCheckpoint, err := catchUpConfiguredRoot(
			ctx,
			scopeID,
			governedRoot,
			summary.TargetUSN,
		)
		summary.USNPasses = passes
		summary.FinalCheckpoint = finalCheckpoint
		if err != nil {
			return summary, err
		}
		return summary, nil
	}

	return summary, errors.New("unreachable configured-root state")
}

func catchUpConfiguredRoot(
	ctx context.Context,
	scopeID string,
	governedRoot string,
	targetUSN string,
) ([]usnSpoolNextSummary, *checkpoint.USNCheckpoint, error) {
	statePath, err := checkpoint.DefaultPath(scopeID)
	if err != nil {
		return nil, nil, err
	}
	current, err := checkpoint.Load(statePath)
	if err != nil {
		return nil, nil, err
	}

	passes := []usnSpoolNextSummary{}
	for {
		if err := ctx.Err(); err != nil {
			return passes, &current, err
		}

		comparison, err := compareUSN(current.NextUSN, targetUSN)
		if err != nil {
			return passes, &current, err
		}
		if comparison >= 0 {
			return passes, &current, nil
		}

		previousUSN := current.NextUSN
		pass, err := writeUSNSpoolNext(ctx, scopeID, governedRoot)
		passes = append(passes, pass)
		if err != nil {
			return passes, &current, err
		}
		if !pass.CheckpointAdvanced || pass.AdvancedCheckpoint == nil {
			return passes, &current, errors.New("USN catch-up pass did not advance its checkpoint")
		}
		current = *pass.AdvancedCheckpoint

		progress, err := compareUSN(current.NextUSN, previousUSN)
		if err != nil {
			return passes, &current, err
		}
		if progress <= 0 {
			return passes, &current, fmt.Errorf("USN catch-up made no forward progress from %s", previousUSN)
		}
	}
}

// configuredScopeID derives a stable local scope identifier without expanding
// the v1 configuration format. Windows governed-root paths are case-insensitive,
// so equivalent case/trailing-slash spellings intentionally map to the same ID.
// The original governed-root path remains present in every observation.
func configuredScopeID(governedRoot string) string {
	canonical := strings.TrimRight(strings.TrimSpace(governedRoot), `\`)
	if len(canonical) == 2 && canonical[1] == ':' {
		canonical += `\`
	}
	canonical = strings.ToLower(canonical)

	digest := sha256.Sum256([]byte(canonical))
	return "root-" + hex.EncodeToString(digest[:16])
}

func compareUSN(left string, right string) (int, error) {
	leftValue, err := strconv.ParseUint(left, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse USN %q: %w", left, err)
	}
	rightValue, err := strconv.ParseUint(right, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse USN %q: %w", right, err)
	}

	switch {
	case leftValue < rightValue:
		return -1, nil
	case leftValue > rightValue:
		return 1, nil
	default:
		return 0, nil
	}
}

func fileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, os.ErrNotExist):
		return false, nil
	default:
		return false, err
	}
}
