// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const InterruptedDirName = "interrupted"

type InterruptedArtifactKind string

const (
	InterruptedOpenData       InterruptedArtifactKind = "OpenData"
	InterruptedOpenManifest   InterruptedArtifactKind = "OpenManifest"
	InterruptedOrphanData     InterruptedArtifactKind = "OrphanFinalizedData"
	InterruptedOrphanManifest InterruptedArtifactKind = "OrphanFinalizedManifest"
)

type PreservedInterruptedArtifact struct {
	BatchID       string                  `json:"batch_id"`
	Kind          InterruptedArtifactKind `json:"kind"`
	OriginalPath  string                  `json:"original_path"`
	PreservedPath string                  `json:"preserved_path"`
}

type InterruptedRecoverySummary struct {
	SpoolDir       string                         `json:"spool_dir"`
	InterruptedDir string                         `json:"interrupted_dir"`
	PreservedCount int                            `json:"preserved_count"`
	Preserved      []PreservedInterruptedArtifact `json:"preserved"`
}

type batchArtifacts struct {
	dataOpen      string
	manifestOpen  string
	dataFinal     string
	manifestFinal string
}

// PreserveInterruptedArtifacts mechanically preserves FI-owned spool artifacts
// that cannot represent a fully finalized batch.
//
// The caller must already hold exclusive collector runtime ownership. This
// function never invents or reconstructs a manifest, never promotes an
// interrupted artifact into an accepted batch, never deletes the bytes, and
// never advances a source checkpoint. Finalized data+manifest pairs are left
// untouched; their normal verification semantics remain unchanged.
func PreserveInterruptedArtifacts(dir string) (InterruptedRecoverySummary, error) {
	if strings.TrimSpace(dir) == "" {
		return InterruptedRecoverySummary{}, errors.New("spool directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return InterruptedRecoverySummary{}, err
	}

	interruptedDir := filepath.Join(dir, InterruptedDirName)
	summary := InterruptedRecoverySummary{
		SpoolDir:       dir,
		InterruptedDir: interruptedDir,
		Preserved:      []PreservedInterruptedArtifact{},
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return summary, err
	}

	batches := make(map[string]*batchArtifacts)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		batchID, kind, ok := classifySpoolArtifact(entry.Name())
		if !ok {
			continue
		}
		artifacts := batches[batchID]
		if artifacts == nil {
			artifacts = &batchArtifacts{}
			batches[batchID] = artifacts
		}

		path := filepath.Join(dir, entry.Name())
		switch kind {
		case InterruptedOpenData:
			artifacts.dataOpen = path
		case InterruptedOpenManifest:
			artifacts.manifestOpen = path
		case InterruptedOrphanData:
			artifacts.dataFinal = path
		case InterruptedOrphanManifest:
			artifacts.manifestFinal = path
		}
	}

	batchIDs := make([]string, 0, len(batches))
	for batchID := range batches {
		batchIDs = append(batchIDs, batchID)
	}
	sort.Strings(batchIDs)

	for _, batchID := range batchIDs {
		artifacts := batches[batchID]

		toPreserve := []struct {
			kind InterruptedArtifactKind
			path string
		}{
			{InterruptedOpenData, artifacts.dataOpen},
			{InterruptedOpenManifest, artifacts.manifestOpen},
		}

		if artifacts.dataFinal != "" && artifacts.manifestFinal == "" {
			toPreserve = append(toPreserve, struct {
				kind InterruptedArtifactKind
				path string
			}{InterruptedOrphanData, artifacts.dataFinal})
		}
		if artifacts.manifestFinal != "" && artifacts.dataFinal == "" {
			toPreserve = append(toPreserve, struct {
				kind InterruptedArtifactKind
				path string
			}{InterruptedOrphanManifest, artifacts.manifestFinal})
		}

		for _, artifact := range toPreserve {
			if artifact.path == "" {
				continue
			}
			preserved, err := preserveInterruptedArtifact(
				interruptedDir,
				batchID,
				artifact.kind,
				artifact.path,
			)
			if err != nil {
				return summary, err
			}
			summary.Preserved = append(summary.Preserved, preserved)
			summary.PreservedCount++
		}
	}

	return summary, nil
}

func classifySpoolArtifact(name string) (string, InterruptedArtifactKind, bool) {
	if !strings.HasPrefix(name, "batch-") {
		return "", "", false
	}

	for _, candidate := range []struct {
		suffix string
		kind   InterruptedArtifactKind
	}{
		{".manifest.json.open", InterruptedOpenManifest},
		{".manifest.json", InterruptedOrphanManifest},
		{".jsonl", InterruptedOrphanData},
		{".open", InterruptedOpenData},
	} {
		if !strings.HasSuffix(name, candidate.suffix) {
			continue
		}
		batchID := strings.TrimSuffix(strings.TrimPrefix(name, "batch-"), candidate.suffix)
		if batchID == "" {
			return "", "", false
		}
		return batchID, candidate.kind, true
	}

	return "", "", false
}

func preserveInterruptedArtifact(
	interruptedDir string,
	batchID string,
	kind InterruptedArtifactKind,
	source string,
) (PreservedInterruptedArtifact, error) {
	batchDir := filepath.Join(interruptedDir, batchID)
	if err := os.MkdirAll(batchDir, 0o700); err != nil {
		return PreservedInterruptedArtifact{}, err
	}

	destination := filepath.Join(batchDir, filepath.Base(source))
	if _, err := os.Stat(destination); err == nil {
		return PreservedInterruptedArtifact{}, fmt.Errorf(
			"interrupted spool destination already exists: %s",
			destination,
		)
	} else if !errors.Is(err, os.ErrNotExist) {
		return PreservedInterruptedArtifact{}, err
	}

	if err := durableRename(source, destination); err != nil {
		return PreservedInterruptedArtifact{}, fmt.Errorf(
			"preserve interrupted spool artifact %q: %w",
			source,
			err,
		)
	}

	return PreservedInterruptedArtifact{
		BatchID:       batchID,
		Kind:          kind,
		OriginalPath:  source,
		PreservedPath: destination,
	}, nil
}
