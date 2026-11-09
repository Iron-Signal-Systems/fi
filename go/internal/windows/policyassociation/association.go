// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package policyassociation evaluates governed-root membership for a single
// independently enrolled volume. It is a pure observation component: a
// membership is NOT permission to open an object, elevate a collector, or
// infer historical path containment from a current NTFS namespace.
package policyassociation

import (
	"errors"
	"fmt"
	"sort"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
)

// FileID holds the canonical 128-bit NTFS object identity used by a future
// native lineage resolver. USN_RECORD_V2 64-bit references MUST be converted
// and reconciled explicitly; they are not interchangeable with a path, name,
// or unverified FILE_ID_INFO value.
type FileID [16]byte

// RootBinding represents the native-resolution result for ONE configured
// governed root. Native code must verify volume identity, directory identity,
// reparse handling and policy-root containment before constructing bindings.
// Calling NewPlan with arbitrary bindings cannot confer privileged authority.
type RootBinding struct {
	PolicyID string
	VolumeID string
	RootID   FileID
}

// Evidence is a single independently established object lineage on the
// stated volume. Ancestors are immediate parent first, excluding ObjectID.
// Complete must only be set after native handle-based ancestry resolution;
// a rename, deletion, hard link or reparse boundary may make it unknowable.
// This object is NOT a capability or an FIObjReader authorization token.
type Evidence struct {
	VolumeID               string
	VolumeGUID             string
	VolumeSerial           string
	ObjectID               FileID
	Ancestors              []FileID
	Complete               bool
	CrossedReparseBoundary bool
}

type Status string

const (
	Matched Status = "Matched"
	Outside Status = "Outside"
	Unknown Status = "Unknown"
)

var (
	ErrInvalidBindings = errors.New("invalid FI governed-root native bindings")
	ErrInvalidEvidence = errors.New("invalid FI governed-root lineage evidence")
)

const maxLineageAncestors = 1024

// Membership is a policy-specific observation association, NOT an effective
// permission. Overlapping policies remain distinct; their depths must never
// be merged into a broader read permission by this component.
type Membership struct {
	PolicyID string
	Depth    config.PolicyDepth
}

type Result struct {
	Status      Status
	Memberships []Membership
}

type boundPolicy struct {
	rootID FileID
	info   Membership
}

type boundVolume struct {
	guid     string
	serial   string
	policies []boundPolicy
}

// Plan stores a defensive immutable copy of explicit enrollments and
// independently resolved policy roots. Neither the incoming config nor
// binding slices are retained. Plan has no method that performs Windows I/O.
type Plan struct {
	volumes map[string]boundVolume
}

// NewPlan requires one native binding per configured root, and none for
// undeclared policies. A repeated native root identity under two policy IDs
// is ambiguous aliasing and requires an explicit operator scope review.
func NewPlan(approved config.VolumeConfig, roots []RootBinding) (Plan, error) {
	if _, err := config.CanonicalVolumeV2(approved); err != nil {
		return Plan{}, fmt.Errorf("%w: malformed approved volume scope: %v", ErrInvalidBindings, err)
	}
	out := Plan{volumes: make(map[string]boundVolume, len(approved.Volumes))}
	for _, volume := range approved.Volumes {
		out.volumes[volume.ID] = boundVolume{guid: volume.GUID, serial: volume.Serial}
	}
	declared := make(map[string]config.RootPolicy, len(approved.Policies))
	for _, policy := range approved.Policies {
		declared[policy.ID] = policy
	}
	if len(roots) != len(declared) {
		return Plan{}, fmt.Errorf("%w: every declared root requires exactly one native identity", ErrInvalidBindings)
	}
	seenPolicy := make(map[string]bool, len(roots))
	seenRoot := make(map[string]map[FileID]bool, len(out.volumes))
	for _, root := range roots {
		policy, ok := declared[root.PolicyID]
		if !ok || seenPolicy[root.PolicyID] || policy.VolumeID != root.VolumeID || root.RootID == (FileID{}) {
			return Plan{}, fmt.Errorf("%w: missing, repeated, misplaced or zero root identity for %q", ErrInvalidBindings, root.PolicyID)
		}
		seenPolicy[root.PolicyID] = true
		if seenRoot[root.VolumeID] == nil {
			seenRoot[root.VolumeID] = make(map[FileID]bool)
		}
		if seenRoot[root.VolumeID][root.RootID] {
			return Plan{}, fmt.Errorf("%w: multiple policies resolve to one native directory on volume %q", ErrInvalidBindings, root.VolumeID)
		}
		seenRoot[root.VolumeID][root.RootID] = true
		volume := out.volumes[root.VolumeID]
		volume.policies = append(volume.policies, boundPolicy{
			rootID: root.RootID,
			info:   Membership{PolicyID: policy.ID, Depth: policy.Depth},
		})
		out.volumes[root.VolumeID] = volume
	}
	for id, volume := range out.volumes {
		sort.Slice(volume.policies, func(i, j int) bool {
			return volume.policies[i].info.PolicyID < volume.policies[j].info.PolicyID
		})
		out.volumes[id] = volume
	}
	return out, nil
}

// Evaluate associates one trusted observation lineage with each matching
// policy at most once. Missing ancestry is Unknown, never proof of Outside.
// A reparse crossing makes the whole proposed containment proof unusable.
// No path-prefix fallback or implicit other-volume enrollment is permitted.
func (plan Plan) Evaluate(e Evidence) (Result, error) {
	volume, enrolled := plan.volumes[e.VolumeID]
	if !enrolled || e.VolumeGUID != volume.guid || e.VolumeSerial != volume.serial {
		return Result{}, fmt.Errorf("%w: volume identity is not the approved enrollment", ErrInvalidEvidence)
	}
	if e.ObjectID == (FileID{}) || len(e.Ancestors) > maxLineageAncestors {
		return Result{}, fmt.Errorf("%w: missing object identity or overlong lineage", ErrInvalidEvidence)
	}
	// Reject cycles and repeated identifiers even for incomplete evidence:
	// such evidence cannot establish a trustworthy parent-child chain.
	identities := map[FileID]bool{e.ObjectID: true}
	for _, ancestor := range e.Ancestors {
		if ancestor == (FileID{}) || identities[ancestor] {
			return Result{}, fmt.Errorf("%w: zero, cyclic or repeated ancestor", ErrInvalidEvidence)
		}
		identities[ancestor] = true
	}
	if len(volume.policies) == 0 {
		return Result{Status: Outside}, nil
	}
	if !e.Complete || e.CrossedReparseBoundary {
		return Result{Status: Unknown}, nil
	}
	result := Result{Status: Outside}
	for _, policy := range volume.policies {
		if identities[policy.rootID] {
			result.Memberships = append(result.Memberships, policy.info)
		}
	}
	if len(result.Memberships) > 0 {
		result.Status = Matched
	}
	return result, nil
}
