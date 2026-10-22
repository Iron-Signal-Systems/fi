// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

// PublicationCustodyKind identifies where complete original FI batch pairs
// could be reverified at inspection time. This is NOT an acknowledgement or a
// durable generation receipt. A sender may seal/retire a raw generation during
// this inspection without holding the collector's publication boundary.
type PublicationCustodyKind string

const (
	PublicationCustodyActive    PublicationCustodyKind = "ActiveSpool"
	PublicationCustodyFrozenRaw PublicationCustodyKind = "FrozenRawGeneration"
)

type PublicationCustodyLocation struct {
	Kind          PublicationCustodyKind `json:"kind"`
	Directory     string                 `json:"directory"`
	ManifestPaths []string               `json:"manifest_paths"`
}

// InspectPendingPublicationCustody finds complete, verified, source-bound
// manifests in either the active FI spool or FI sender's frozen raw generations.
// It is READ-ONLY: it never commits a processing cursor or authorizes retry.
// Absence cannot prove nonpublication: a generation might already be sealed,
// transmitted, acknowledged, or retired. In that case ErrPublicationPending
// is returned. Callers must never republish based on this result.
//
// This M5A inspector intentionally does not inspect or trust sealed generation
// metadata, compressed transport bytes, or receiver acknowledgements. An
// authoritative source-bound ledger is needed to prove those later states.
func (s *Store) InspectPendingPublicationCustody(
	seg Segment, corr Correlation, spoolDir string,
) ([]PublicationCustodyLocation, error) {
	pending, err := s.PublicationPending(seg, corr)
	if err != nil {
		return nil, err
	}
	if !pending {
		return nil, fmt.Errorf("%w: no pending publication intent", ErrConflict)
	}
	// This guards active-spool rollover only. The raw-generation builder may
	// still move and delete frozen data while inspecting; any read failure
	// must remain fail-closed, never be taken as permission to republish.
	guard, err := spool.AcquirePublishBoundary()
	if err != nil {
		return nil, err
	}
	defer guard.Close()

	physical, err := spool.PhysicalSpoolDir(spoolDir)
	if err != nil {
		return nil, err
	}
	var locations []PublicationCustodyLocation
	active, err := scanSpoolPublication(seg, corr, physical)
	if err != nil {
		return nil, err
	}
	if len(active) != 0 {
		locations = append(locations, PublicationCustodyLocation{
			Kind: PublicationCustodyActive, Directory: physical, ManifestPaths: active,
		})
	}

	rawRoot := filepath.Join(filepath.Dir(physical), "generation-raw")
	rawInfo, err := os.Lstat(rawRoot)
	if errors.Is(err, os.ErrNotExist) {
		if len(locations) == 0 {
			return nil, ErrPublicationPending
		}
		return locations, nil
	}
	if err != nil {
		return nil, err
	}
	if !rawInfo.IsDir() || rawInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: raw generation root is not a real directory", ErrCorrupt)
	}
	entries, err := os.ReadDir(rawRoot)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "generation-") ||
			len(entry.Name()) <= len("generation-") {
			return nil, fmt.Errorf("%w: unexpected raw generation entry", ErrCorrupt)
		}
		path := filepath.Join(rawRoot, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: raw generation is not a real directory", ErrCorrupt)
		}
		manifests, err := scanSpoolPublication(seg, corr, path)
		if err != nil {
			return nil, err
		}
		if len(manifests) != 0 {
			locations = append(locations, PublicationCustodyLocation{
				Kind: PublicationCustodyFrozenRaw, Directory: path, ManifestPaths: manifests,
			})
		}
	}
	if len(locations) == 0 {
		return nil, ErrPublicationPending
	}
	return locations, nil
}
