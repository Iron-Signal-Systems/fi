// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/policyassociation"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumediscovery"
)

// rootAttestor is an intentionally read-only native observation dependency.
// Its result is untrusted until every binding is checked against the exact
// selected v2 declaration; it cannot authenticate operator installation consent.
type rootAttestor func(context.Context, config.VolumeConfig, string) ([]policyassociation.RootBinding, error)

type rootIdentityReport struct {
	PolicyID     string `json:"policy_id"`
	FileID128Hex string `json:"file_id_128_hex"`
}

type volumeRootInspection struct {
	EnrollmentID string               `json:"enrollment_id"`
	Status       string               `json:"status"`
	Detail       string               `json:"detail,omitempty"`
	Identities   []rootIdentityReport `json:"policy_root_identities"`
}

// inspectRequestedPolicyRoots deliberately checks every enrolled volume
// independently. A failed/offline volume blocks the overall preflight but
// does not prevent read-only evidence from healthy volumes. Failed volumes
// return no partial or stale identities, even if the underlying observer
// performed some successful reads before its error.
func inspectRequestedPolicyRoots(
	ctx context.Context,
	scope config.VolumeConfig,
	matches []volumediscovery.Match,
	inspect rootAttestor,
) ([]volumeRootInspection, bool, error) {
	if ctx == nil || inspect == nil {
		return nil, false, fmt.Errorf("root preflight requires a context and read-only native observer")
	}
	if _, err := config.CanonicalVolumeV2(scope); err != nil {
		return nil, false, fmt.Errorf("invalid v2 policy root declaration: %w", err)
	}
	if len(matches) != len(scope.Volumes) {
		return nil, false, fmt.Errorf("incomplete native enrollment comparison for governed-root inspection")
	}
	byID := make(map[string]volumediscovery.Match, len(matches))
	for _, item := range matches {
		if _, duplicate := byID[item.EnrollmentID]; duplicate {
			return nil, false, fmt.Errorf("duplicate native enrollment comparison for %q", item.EnrollmentID)
		}
		byID[item.EnrollmentID] = item
	}
	out := make([]volumeRootInspection, 0, len(scope.Volumes))
	allVerified := true
	for _, volume := range scope.Volumes {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		match, found := byID[volume.ID]
		if !found || match.GUID != volume.GUID {
			return nil, false, fmt.Errorf("missing or inconsistent native comparison for enrolled volume %q", volume.ID)
		}
		item := volumeRootInspection{
			EnrollmentID: volume.ID,
			Identities:   []rootIdentityReport{},
		}
		if match.Status != volumediscovery.IdentityMatched {
			item.Status = "VolumeNotMatched"
			item.Detail = string(match.Status) + ": " + match.Detail
			out = append(out, item)
			allVerified = false
			continue
		}
		identities, err := inspect(ctx, scope, volume.ID)
		if err == nil {
			// This does not authorize a file read: it rejects missing,
			// unexpected, duplicate, zero and cross-volume root bindings.
			_, err = policyassociation.NewVolumePlan(scope, volume.ID, identities)
		}
		if err != nil {
			item.Status = "RootAttestationFailed"
			item.Detail = err.Error()
			out = append(out, item)
			allVerified = false
			continue
		}
		if len(identities) == 0 {
			item.Status = "NoPolicies"
		} else {
			item.Status = "IdentitiesObserved"
			for _, binding := range identities {
				item.Identities = append(item.Identities, rootIdentityReport{
					PolicyID: binding.PolicyID,
					FileID128Hex: hex.EncodeToString(binding.RootID[:]),
				})
			}
			// Stable output regardless of the native observer's iteration.
			sort.Slice(item.Identities, func(i, j int) bool {
				return item.Identities[i].PolicyID < item.Identities[j].PolicyID
			})
		}
		out = append(out, item)
	}
	return out, allVerified, nil
}
