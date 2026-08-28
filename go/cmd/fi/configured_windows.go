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
	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/checkpoint"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usn"
)

type configuredRootAction string
type configuredRootStatus string

const (
	configuredActionBaselineAndCatchUp             configuredRootAction = "BaselineAndCatchUp"
	configuredActionGapReconcileBaselineAndCatchUp configuredRootAction = "GapReconcileBaselineAndCatchUp"
	configuredActionUSNCatchUp                     configuredRootAction = "USNCatchUp"
	configuredStatusComplete                       configuredRootStatus = "Complete"
	configuredStatusPartial                        configuredRootStatus = "Partial"
	configuredStatusFailed                         configuredRootStatus = "Failed"
)

type configuredRootSummary struct {
	GovernedRoot        string                               `json:"governed_root"`
	ScopeID             string                               `json:"scope_id"`
	StatePath           string                               `json:"state_path"`
	OperationJournal    string                               `json:"operation_journal"`
	RecoveredOperations []records.OperationRecord            `json:"recovered_operations"`
	Operations          []records.OperationRecord            `json:"operations"`
	CheckpointFound     bool                                 `json:"checkpoint_found"`
	Action              configuredRootAction                 `json:"action"`
	Status              configuredRootStatus                 `json:"status"`
	TargetUSN           string                               `json:"target_usn,omitempty"`
	Gap                 *records.USNContinuityGapObservation `json:"continuity_gap,omitempty"`
	GapSpool            *usnGapSpoolSummary                  `json:"continuity_gap_spool,omitempty"`
	Baseline            *baselineSpoolSummary                `json:"baseline,omitempty"`
	USNPasses           []usnSpoolNextSummary                `json:"usn_passes"`
	FinalCheckpoint     *checkpoint.USNCheckpoint            `json:"final_checkpoint,omitempty"`
	Error               string                               `json:"error,omitempty"`
}

type configuredRunSummary struct {
	ConfigPath                       string                           `json:"config_path"`
	VersionID                        string                           `json:"version_id"`
	ConfiguredRoots                  int                              `json:"configured_roots"`
	CompletedRoots                   int                              `json:"completed_roots"`
	PartialRoots                     int                              `json:"partial_roots"`
	FailedRoots                      int                              `json:"failed_roots"`
	Complete                         bool                             `json:"complete"`
	MonitoringPrerequisitesSatisfied bool                             `json:"monitoring_prerequisites_satisfied"`
	SpoolRecovery                    spool.InterruptedRecoverySummary `json:"spool_recovery"`
	WindowsSecurity                  configuredSecuritySummary        `json:"windows_security"`
	Roots                            []configuredRootSummary          `json:"roots"`
	Semantics                        string                           `json:"semantics"`
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
	summary := configuredRunSummary{ConfigPath: configPath, VersionID: value.VersionID, ConfiguredRoots: len(value.GovernedRoots), Complete: true, Roots: make([]configuredRootSummary, 0, len(value.GovernedRoots)), Semantics: "FI processes Windows Security activity and each configured governed root as independent source observations. Major configured operations use append-only Started/Finished lifecycle journals so an unclosed operation is explicitly recovered as Interrupted after process restart. Interrupted FI spool artifacts are preserved separately and are never promoted into accepted batches or used to advance source checkpoints. Source facts, continuity gaps, checkpoints, spool recovery state, and operation lifecycle records remain separate records with separate meanings."}
	spoolDir, err := spool.DefaultDir()
	if err != nil {
		summary.Complete = false
		return summary, err
	}
	spoolRecovery, err := spool.PreserveInterruptedArtifacts(spoolDir)
	summary.SpoolRecovery = spoolRecovery
	if err != nil {
		summary.Complete = false
		return summary, fmt.Errorf("preserve interrupted spool artifacts: %w", err)
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
	summary := configuredRootSummary{GovernedRoot: governedRoot, ScopeID: scopeID, StatePath: statePath, RecoveredOperations: []records.OperationRecord{}, Operations: []records.OperationRecord{}, USNPasses: []usnSpoolNextSummary{}}
	journalPath, recovered, err := recoverConfiguredOperations(scopeID)
	summary.OperationJournal = journalPath
	summary.RecoveredOperations = recovered
	if err != nil {
		return summary, err
	}
	checkpointFound, err := fileExists(statePath)
	if err != nil {
		return summary, err
	}
	summary.CheckpointFound = checkpointFound
	switch checkpointFound {
	case false:
		summary.Action = configuredActionBaselineAndCatchUp
		return baselineAndCatchUpConfiguredRoot(ctx, summary, records.OperationBaseline)
	case true:
		assessment, err := checkpoint.Check(ctx, scopeID, governedRoot, statePath)
		if err != nil {
			return summary, err
		}
		if assessment.Status == checkpoint.ContinuityGap {
			summary.Action = configuredActionGapReconcileBaselineAndCatchUp
			gap, err := newUSNContinuityGapObservation(governedRoot, assessment)
			if err != nil {
				return summary, err
			}
			if err := records.ValidateUSNContinuityGapObservation(gap); err != nil {
				return summary, err
			}
			summary.Gap = &gap
			gapSpool, err := writeUSNContinuityGap(gap)
			summary.GapSpool = &gapSpool
			if err != nil {
				return summary, err
			}
			return baselineAndCatchUpConfiguredRoot(ctx, summary, records.OperationReconciliation)
		}
		summary.Action = configuredActionUSNCatchUp
		summary.TargetUSN = assessment.JournalState.NextUSN
		var passes []usnSpoolNextSummary
		var finalCheckpoint *checkpoint.USNCheckpoint
		opRecord, opErr := runConfiguredOperation(scopeID, records.OperationUSNCatchUp, func() error {
			var err error
			passes, finalCheckpoint, err = catchUpConfiguredRoot(usn.WithoutInterruptedRecovery(ctx), scopeID, governedRoot, summary.TargetUSN)
			return err
		})
		summary.Operations = appendConfiguredOperation(summary.Operations, opRecord)
		summary.USNPasses = passes
		summary.FinalCheckpoint = finalCheckpoint
		if opErr != nil {
			return summary, opErr
		}
		if configuredUSNPassesPartial(summary.USNPasses) {
			summary.Status = configuredStatusPartial
		}
		return summary, nil
	}
	return summary, errors.New("unreachable configured-root state")
}

func baselineAndCatchUpConfiguredRoot(ctx context.Context, summary configuredRootSummary, baselineKind records.OperationKind) (configuredRootSummary, error) {
	var baseline baselineSpoolSummary
	opRecord, opErr := runConfiguredOperation(summary.ScopeID, baselineKind, func() error {
		var err error
		baseline, err = writeBaselineSpoolRoot(usn.WithoutInterruptedRecovery(ctx), summary.ScopeID, summary.GovernedRoot)
		summary.Baseline = &baseline
		if err != nil {
			return err
		}
		if baseline.PostBaselineAssessment == nil || baseline.Checkpoint == nil {
			return errors.New("successful baseline did not return checkpoint continuity state")
		}
		return nil
	})
	summary.Operations = appendConfiguredOperation(summary.Operations, opRecord)
	if opErr != nil {
		return summary, opErr
	}
	summary.TargetUSN = baseline.PostBaselineAssessment.JournalState.NextUSN
	var passes []usnSpoolNextSummary
	var finalCheckpoint *checkpoint.USNCheckpoint
	opRecord, opErr = runConfiguredOperation(summary.ScopeID, records.OperationUSNCatchUp, func() error {
		var err error
		passes, finalCheckpoint, err = catchUpConfiguredRoot(usn.WithoutInterruptedRecovery(ctx), summary.ScopeID, summary.GovernedRoot, summary.TargetUSN)
		return err
	})
	summary.Operations = appendConfiguredOperation(summary.Operations, opRecord)
	summary.USNPasses = passes
	summary.FinalCheckpoint = finalCheckpoint
	if opErr != nil {
		return summary, opErr
	}
	if configuredUSNPassesPartial(summary.USNPasses) {
		summary.Status = configuredStatusPartial
	}
	return summary, nil
}

func catchUpConfiguredRoot(ctx context.Context, scopeID, governedRoot, targetUSN string) ([]usnSpoolNextSummary, *checkpoint.USNCheckpoint, error) {
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

// configuredUSNPassesPartial marks an operationally accepted USN catch-up as
// Partial when FI durably preserved a real collection failure for a selected
// governed object. Object disappearance and explicit scope uncertainty remain
// source facts and do not, by themselves, mean the collector operation failed.
func configuredUSNPassesPartial(passes []usnSpoolNextSummary) bool {
	for _, pass := range passes {
		if pass.ReobservationErrors > 0 || pass.HashErrors > 0 {
			return true
		}
	}
	return false
}

func configuredScopeID(governedRoot string) string {
	canonical := strings.TrimRight(strings.TrimSpace(governedRoot), `\`)
	if len(canonical) == 2 && canonical[1] == ':' {
		canonical += `\`
	}
	canonical = strings.ToLower(canonical)
	digest := sha256.Sum256([]byte(canonical))
	return "root-" + hex.EncodeToString(digest[:16])
}

func compareUSN(left, right string) (int, error) {
	lv, err := strconv.ParseUint(left, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse USN %q: %w", left, err)
	}
	rv, err := strconv.ParseUint(right, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse USN %q: %w", right, err)
	}
	switch {
	case lv < rv:
		return -1, nil
	case lv > rv:
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
