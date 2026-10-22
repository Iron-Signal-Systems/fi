// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/checkpoint"
)

// This is an explicit, lab-only replacement for FICollector's synchronous
// USN lane. The existing source checkpoint is immutable while the lab queue
// owns the scope. No automatic migration, rebasing or fallback is permitted.
const (
	labPipelineEnv       = "FI_USN_PIPELINE_LAB"
	labQueuePrefix       = "usn-capture-"
	labAnchorName        = "legacy-anchor.json"
	labAnchorVersion     = "fi-usn-lab-anchor/1"
	labIdleInterval      = 200 * time.Millisecond
	labTelemetryInterval = 10 * time.Second
)

type labAnchor struct {
	Version    string                   `json:"version"`
	Root       string                   `json:"root"`
	Checkpoint checkpoint.USNCheckpoint `json:"checkpoint"`
}

type labPipelineRoot struct {
	root      string
	scope     string
	statePath string
	store     *usncapture.Store
}

func labPipelineRequested() (bool, error) {
	value := strings.TrimSpace(os.Getenv(labPipelineEnv))
	switch value {
	case "":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("%s must be unset or exactly 1", labPipelineEnv)
	}
}

func labPipelineQueueDir(stateDir, scopeID string) (string, error) {
	if !filepath.IsAbs(stateDir) || scopeID == "" ||
		strings.ContainsAny(scopeID, `\\/.:`) {
		return "", errors.New("invalid lab queue state directory or scope identity")
	}
	return filepath.Join(stateDir, labQueuePrefix+scopeID), nil
}

func guardLegacyUSNRoot(root string) error {
	scopeID := configuredScopeID(root)
	statePath, err := checkpoint.DefaultPath(scopeID)
	if err != nil {
		return err
	}
	dir, err := labPipelineQueueDir(filepath.Dir(statePath), scopeID)
	if err != nil {
		return err
	}
	_, err = os.Lstat(dir)
	if err == nil {
		return fmt.Errorf("FI lab queue exists for %s: legacy USN or baseline writer is prohibited until an explicitly reviewed migration", root)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// runUSNPipelineLabInit is an explicit operator action, while the runtime
// ownership lock is held and the legacy service is stopped. The existing
// checkpoint must already have a verified baseline and continuous USN history.
func runUSNPipelineLabInit(ctx context.Context, root string) error {
	configured, _, err := config.LoadDefault()
	if err != nil {
		return err
	}
	selected := false
	for _, governed := range configured.GovernedRoots {
		if strings.EqualFold(filepath.Clean(governed), filepath.Clean(root)) {
			selected = true
			root = governed
			break
		}
	}
	if !selected {
		return errors.New("root is not approved in the active FI configuration")
	}
	scopeID := configuredScopeID(root)
	path, err := checkpoint.DefaultPath(scopeID)
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Clean(filepath.Dir(path)), filepath.Clean(configured.Storage.StateDir)) {
		return errors.New("FI_STATE_DIR and configured state directory disagree")
	}
	assessment, err := checkpoint.Check(ctx, scopeID, root, path)
	if err != nil {
		return err
	}
	if assessment.Status != checkpoint.ContinuityContinuous {
		return fmt.Errorf("refuse lab migration: original FI checkpoint has continuity gap %q; baseline/reconcile first", assessment.ReasonCode)
	}
	dir, err := labPipelineQueueDir(configured.Storage.StateDir, scopeID)
	if err != nil {
		return err
	}
	anchor := usncapture.Cursor{
		Version:        usncapture.SchemaVersion,
		ScopeID:        scopeID,
		JournalID:      assessment.Checkpoint.JournalID,
		VolumeIdentity: assessment.Checkpoint.GovernedRoot.VolumeIdentity,
		NextUSN:        assessment.Checkpoint.NextUSN,
	}
	if err := usncapture.Initialize(dir, anchor); err != nil {
		return err
	}
	// If a failure occurs after queue initialization, startup will fail
	// closed because the anchor is absent. Do not delete and reinitialize.
	receipt := labAnchor{Version: labAnchorVersion, Root: root, Checkpoint: assessment.Checkpoint}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(filepath.Join(dir, labAnchorName), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(encoded)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	closeErr := file.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		return err
	}
	fmt.Printf("FI lab queue initialized: root=%s scope=%s next_usn=%s dir=%s\n", root, scopeID, anchor.NextUSN, dir)
	return nil
}

func openUSNPipelineLabRoot(ctx context.Context, stateDir, root string) (labPipelineRoot, error) {
	scopeID := configuredScopeID(root)
	statePath, err := checkpoint.DefaultPath(scopeID)
	if err != nil {
		return labPipelineRoot{}, err
	}
	if !strings.EqualFold(filepath.Clean(filepath.Dir(statePath)), filepath.Clean(stateDir)) {
		return labPipelineRoot{}, errors.New("lab state directory differs from FI checkpoint directory")
	}
	dir, err := labPipelineQueueDir(stateDir, scopeID)
	if err != nil {
		return labPipelineRoot{}, err
	}
	store, err := usncapture.Open(dir, usncapture.DefaultMaxPendingBytes)
	if err != nil {
		return labPipelineRoot{}, fmt.Errorf("load pre-initialized lab queue %s: %w", scopeID, err)
	}
	f, err := os.Open(filepath.Join(dir, labAnchorName))
	if err != nil {
		return labPipelineRoot{}, err
	}
	raw, readErr := io.ReadAll(io.LimitReader(f, 1<<20+1))
	closeErr := f.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return labPipelineRoot{}, err
	}
	if len(raw) > 1<<20 {
		return labPipelineRoot{}, errors.New("lab anchor exceeds 1 MiB")
	}
	var anchor labAnchor
	if err := json.Unmarshal(raw, &anchor); err != nil {
		return labPipelineRoot{}, err
	}
	original, err := checkpoint.Load(statePath)
	if err != nil {
		return labPipelineRoot{}, err
	}
	if anchor.Version != labAnchorVersion || anchor.Root != root ||
		!reflect.DeepEqual(anchor.Checkpoint, original) {
		return labPipelineRoot{}, errors.New("legacy FI checkpoint changed after lab queue initialization")
	}
	cursor := store.CaptureCursor()
	processed := store.ProcessingCursor()
	if cursor.ScopeID != scopeID || cursor.JournalID != original.JournalID ||
		!reflect.DeepEqual(cursor.VolumeIdentity, original.GovernedRoot.VolumeIdentity) ||
		processed.ScopeID != scopeID {
		return labPipelineRoot{}, errors.New("lab queue cursor identity differs from original baseline")
	}
	assessment, err := checkpoint.Check(ctx, scopeID, root, statePath)
	if err != nil {
		return labPipelineRoot{}, err
	}
	if assessment.CurrentGovernedRoot.ObjectIdentity != original.GovernedRoot.ObjectIdentity ||
		!reflect.DeepEqual(assessment.CurrentGovernedRoot.VolumeIdentity, original.GovernedRoot.VolumeIdentity) ||
		assessment.JournalState.JournalID != cursor.JournalID {
		return labPipelineRoot{}, errors.New("lab governed-root, volume or journal identity changed")
	}
	// Aged-out *legacy* checkpoint is permitted on restart provided the
	// separately durable capture cursor remains continuous. captureUSNOnce
	// evaluates the latter independently on every read.
	return labPipelineRoot{root: root, scope: scopeID, statePath: statePath, store: store}, nil
}

func prepareUSNPipelineLab(ctx context.Context, snapshot serviceOperationalSnapshot) ([]labPipelineRoot, error) {
	if len(snapshot.GovernedRoots) == 0 {
		return nil, errors.New("lab pipeline requires configured governed roots")
	}
	roots := make([]labPipelineRoot, 0, len(snapshot.GovernedRoots))
	for _, root := range snapshot.GovernedRoots {
		value, err := openUSNPipelineLabRoot(ctx, snapshot.StateDir, root)
		if err != nil {
			return nil, fmt.Errorf("prepare lab root %s: %w", root, err)
		}
		roots = append(roots, value)
	}
	return roots, nil
}

func writeLabRootCollectionSummary(snapshot serviceOperationalSnapshot) configuredRunSummary {
	// The lab pipeline owns every configured root; the old synchronous
	// catch-up/baseline lane must not run concurrently.
	return configuredRunSummary{
		ConfigPath: snapshot.ConfigPath, VersionID: snapshot.VersionID,
		ConfiguredRoots: len(snapshot.GovernedRoots),
		PartialRoots:    len(snapshot.GovernedRoots), Complete: false,
		Semantics: "Explicit USN pipeline lab mode: synchronous configured-root collection is disabled; independent durable capture and NTFS processing own each governed root. No baseline or legacy checkpoint advancement is implied.",
	}
}

func labWait(ctx context.Context, interval time.Duration) error {
	t := time.NewTimer(interval)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func runUSNPipelineLab(ctx context.Context, roots []labPipelineRoot, appendRecord serviceAppendRecordFunc) error {
	if len(roots) == 0 {
		return errors.New("no lab USN roots")
	}
	if appendRecord == nil {
		return errors.New("lab runtime logger required")
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsCh := make(chan error, len(roots)*2)
	var workers sync.WaitGroup
	report := func(err error) {
		if err == nil || (errors.Is(err, context.Canceled) && ctx.Err() != nil) {
			return
		}
		select {
		case errorsCh <- err:
		default:
		}
	}
	for _, root := range roots {
		r := root
		workers.Add(2)
		go func() {
			defer workers.Done()
			for workCtx.Err() == nil {
				advanced, err := captureUSNOnce(workCtx, r.scope, r.root, r.store)
				if err != nil {
					report(fmt.Errorf("lab capture %s: %w", r.root, err))
					return
				}
				if !advanced {
					if err := labWait(workCtx, labIdleInterval); err != nil {
						return
					}
				}
			}
		}()
		go func() {
			defer workers.Done()
			// Slow NTFS processing never owns the capture cursor or blocks
			// capture while inspecting an object.
			for workCtx.Err() == nil {
				original, err := checkpoint.Load(r.statePath)
				if err != nil {
					report(fmt.Errorf("lab processing checkpoint %s: %w", r.root, err))
					return
				}
				completed, err := processCapturedUSNOnce(workCtx, r.scope, r.root,
					original.GovernedRoot.ObjectIdentity, r.store, r.statePath)
				if err != nil {
					report(fmt.Errorf("lab NTFS processing %s: %w", r.root, err))
					return
				}
				if completed {
					if _, _, err := r.store.ReclaimAcknowledged(); err != nil {
						report(fmt.Errorf("lab queue reclaim %s: %w", r.root, err))
						return
					}
				} else if err := labWait(workCtx, labIdleInterval); err != nil {
					return
				}
			}
		}()
	}
	ticker := time.NewTicker(labTelemetryInterval)
	defer ticker.Stop()
	finish := func(errorValue error) error { cancel(); workers.Wait(); return errorValue }
	for {
		select {
		case <-ctx.Done():
			return finish(nil)
		case err := <-errorsCh:
			return finish(err)
		case <-ticker.C:
			for _, r := range roots {
				capture := r.store.CaptureCursor()
				processed := r.store.ProcessingCursor()
				outcome := serviceOutcomeComplete
				if capture.NextUSN != processed.NextUSN {
					outcome = serviceOutcomePartial
				}
				if err := appendRecord(serviceRuntimeRecord{
					Version: serviceRuntimeVersion, RecordKind: "USNPipelineLab",
					ObservedAt: serviceNow(), Outcome: outcome,
					LabScopeID: r.scope, LabCaptureNextUSN: capture.NextUSN,
					LabProcessingNextUSN: processed.NextUSN,
				}); err != nil {
					return finish(err)
				}
			}
		}
	}
}
