// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "context"
    "errors"
    "fmt"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
)

// serviceUSNVolumeCapture owns one immutable source stream for a volume. All
// roots on this volume share this same capture/retention cursor, but retain
// their separate governed-root processing identities.
type serviceUSNVolumeCapture struct {
    CaptureScopeID string
    RepresentativeRoot string
    GovernedRoots []string
    JournalID string
    VolumeIdentity records.VolumeIdentity
}

// resolveServiceUSNVolumeCaptures deduplicates configured roots by physical
// NTFS volume. The query runs before any capture queue can be opened or written.
// A conflicting live journal on one volume fails closed.
func resolveServiceUSNVolumeCaptures(ctx context.Context, roots []string, query captureQuery) ([]serviceUSNVolumeCapture, error) {
    if ctx == nil || query == nil || len(roots) == 0 {
        return nil, errors.New("FI volume USN capture roots and journal query required")
    }
    volumes := make([]serviceUSNVolumeCapture, 0, len(roots))
    byVolume := make(map[string]int, len(roots))
    for _, root := range roots {
        if err := ctx.Err(); err != nil {
            return nil, err
        }
        scope := configuredScopeID(root)
        if root == "" || scope == "" {
            return nil, errors.New("FI raw capture root is empty")
        }
        state, err := query(ctx, scope, root)
        if err != nil {
            return nil, fmt.Errorf("query journal for governed root %q: %w", root, err)
        }
        if err := records.ValidateUSNJournalState(state); err != nil {
            return nil, fmt.Errorf("invalid journal for governed root %q: %w", root, err)
        }
        if state.ScopeID != scope {
            return nil, fmt.Errorf("FI raw capture journal query scope mismatch on %q", root)
        }
        volumeScope, err := usncapture.VolumeCaptureScopeID(state.VolumeIdentity)
        if err != nil {
            return nil, err
        }
        if index, ok := byVolume[volumeScope]; ok {
            existing := &volumes[index]
            if existing.JournalID != state.JournalID {
                return nil, fmt.Errorf("FI raw capture volume %s changed journal during discovery", volumeScope)
            }
            existing.GovernedRoots = append(existing.GovernedRoots, root)
            continue
        }
        byVolume[volumeScope] = len(volumes)
        volumes = append(volumes, serviceUSNVolumeCapture{
            CaptureScopeID: volumeScope,
            RepresentativeRoot: root,
            GovernedRoots: []string{root},
            JournalID: state.JournalID,
            VolumeIdentity: state.VolumeIdentity,
        })
    }
    return volumes, nil
}
