// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package policyroot performs read-only governed-root identity observation.
// No method here approves enrollment or authorizes protected-object reads.
package policyroot

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
)

const (
	maxRootWalkComponents = 256
	maxRootWalkPathBytes  = 30000
)

var ErrInvalidRootTarget = errors.New("invalid FI v2 governed-root attestation target")

// target is private: external callers cannot supply an arbitrary native path.
type target struct {
	policyID     string
	volumeID     string
	guid         string
	serial       string
	relativeRoot string
}

// targetsForVolume selects ONLY the exact explicitly enrolled volume.
// This pure check does not authenticate operator approval or installed state.
func targetsForVolume(scope config.VolumeConfig, enrollmentID string) (config.VolumeEnrollment, []target, error) {
	if _, err := config.CanonicalVolumeV2(scope); err != nil {
		return config.VolumeEnrollment{}, nil, fmt.Errorf("%w: invalid scope: %v", ErrInvalidRootTarget, err)
	}
	var selected config.VolumeEnrollment
	found := false
	for _, volume := range scope.Volumes {
		if volume.ID == enrollmentID {
			selected, found = volume, true
			break
		}
	}
	if !found {
		return config.VolumeEnrollment{}, nil, fmt.Errorf("%w: volume %q is not enrolled", ErrInvalidRootTarget, enrollmentID)
	}
	var out []target
	for _, policy := range scope.Policies {
		if policy.VolumeID != selected.ID {
			continue
		}
		item := target{
			policyID: policy.ID, volumeID: selected.ID,
			guid: selected.GUID, serial: selected.Serial,
			relativeRoot: policy.RelativeRoot,
		}
		if _, err := rootWalkPaths(item); err != nil {
			return config.VolumeEnrollment{}, nil, err
		}
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].policyID < out[j].policyID })
	return selected, out, nil
}

// rootWalkPaths supplies only the enrolled volume GUID root and its immediate
// directory prefixes. Every native prefix is separately opened without
// following its final reparse point. No drive alias, UNC, arbitrary device,
// traversal or skipped intermediate directory may be introduced.
func rootWalkPaths(item target) ([]string, error) {
	if item.guid == "" || !strings.HasSuffix(item.guid, `}`) ||
		item.relativeRoot == "" || !strings.HasPrefix(item.relativeRoot, `\`) {
		return nil, fmt.Errorf("%w: malformed volume locator or relative root", ErrInvalidRootTarget)
	}
	paths := []string{item.guid}
	if item.relativeRoot == `\` {
		return paths, nil
	}
	components := strings.Split(item.relativeRoot[1:], `\`)
	if len(components) > maxRootWalkComponents {
		return nil, fmt.Errorf("%w: too many root path components", ErrInvalidRootTarget)
	}
	parent := strings.TrimSuffix(item.guid, `\`)
	for _, component := range components {
		if component == "" || component == "." || component == ".." ||
			strings.ContainsAny(component, `/:*?"<>|\`) ||
			strings.HasSuffix(component, ".") || strings.TrimSpace(component) != component {
			return nil, fmt.Errorf("%w: unsafe root path component", ErrInvalidRootTarget)
		}
		parent += `\` + component
		if len(parent) > maxRootWalkPathBytes {
			return nil, fmt.Errorf("%w: root path exceeds bounded inspection limit", ErrInvalidRootTarget)
		}
		paths = append(paths, parent)
	}
	return paths, nil
}
