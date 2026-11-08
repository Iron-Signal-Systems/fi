// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package volumereview constructs deterministic, strictly read-only review
// evidence for a proposed Windows volume enrollment configuration.
//
// A matching native inventory and SHA-256 review fingerprint are NOT consent,
// installer authorization, an integrity signature, or a reason to start the
// privileged broker. The eventual installer must authenticate operator
// approval, protect the approved manifest, and repeat discovery at apply time.
package volumereview

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumediscovery"
)

const ReviewVersion = "fi-windows-volume-scope-review/1"

// ChangeKind describes the authorization-relevant *requested* scope changes.
// Every kind requires deliberate installer review. Security and content depths
// are different permissions, not a safe ordinal hierarchy.
type ChangeKind string

const (
	VolumeAdded           ChangeKind = "VolumeAdded"
	VolumeRemoved         ChangeKind = "VolumeRemoved"
	VolumeIdentityChanged ChangeKind = "VolumeIdentityChanged"
	PolicyAdded           ChangeKind = "PolicyAdded"
	PolicyRemoved         ChangeKind = "PolicyRemoved"
	PolicyChanged         ChangeKind = "PolicyChanged"
)

// Change contains deterministic typed config facts, not a preapproved action.
type Change struct {
	Kind    ChangeKind `json:"kind"`
	ID      string     `json:"id"`
	Before  string     `json:"before,omitempty"`
	After   string     `json:"after,omitempty"`
}

// NativeIdentity is intentionally restricted to the native fields relevant
// to enrollment. Drive letters and mount paths are aliases and may change
// without changing the approved volume's identity.
type NativeIdentity struct {
	EnrollmentID   string                      `json:"enrollment_id"`
	VolumeGUID     string                      `json:"volume_guid"`
	MatchStatus    volumediscovery.MatchStatus `json:"match_status"`
	NativeStatus   string                      `json:"native_status"`
	NativeSerial64 string                      `json:"native_serial64,omitempty"`
}

// Review is *read-only evidence*. The fingerprint is an unkeyed hash for
// detecting accidental/stale review data, not proof of a trusted issuer.
type Review struct {
	Version                    string           `json:"version"`
	CurrentConfigSHA256        string           `json:"current_config_sha256,omitempty"`
	RequestedConfigSHA256      string           `json:"requested_config_sha256"`
	ReviewFingerprintSHA256    string           `json:"review_fingerprint_sha256"`
	AllRequestedVolumesMatch   bool             `json:"all_requested_volumes_match"`
	BlocksMutation             bool             `json:"blocks_mutation"`
	RequiresExplicitApproval   bool             `json:"requires_explicit_approval"`
	Changes                    []Change         `json:"changes"`
	NativeIdentities           []NativeIdentity `json:"native_identities"`
}

// ErrStaleReview is emitted when either requested policy or observed native
// identity differs from the exact snapshot used to prepare an earlier review.
var ErrStaleReview = errors.New("FI Windows volume review is stale")

// Build validates both supplied scope declarations and the entire native
// inventory before describing any change. Existing must be a trusted installed
// baseline when supplied by a future installer; this package DOES NOT verify
// that trust and never grants any privilege.
func Build(existing *config.VolumeConfig, requested config.VolumeConfig, native []volumediscovery.Snapshot) (Review, error) {
	if len(native) == 0 {
		return Review{}, errors.New("FI volume review requires a nonempty native discovery snapshot")
	}
	proposedBytes, err := config.CanonicalVolumeV2(requested)
	if err != nil {
		return Review{}, fmt.Errorf("requested volume config invalid: %w", err)
	}
	var oldBytes []byte
	if existing != nil {
		oldBytes, err = config.CanonicalVolumeV2(*existing)
		if err != nil {
			return Review{}, fmt.Errorf("installed volume baseline invalid: %w", err)
		}
	}
	preflight, err := volumediscovery.AssessEnrollment(requested, native)
	if err != nil {
		return Review{}, fmt.Errorf("volume review discovery failed: %w", err)
	}

	out := Review{
		Version:                  ReviewVersion,
		RequestedConfigSHA256:    digestHex(proposedBytes),
		AllRequestedVolumesMatch: preflight.AllVolumesMatch,
		BlocksMutation:           !preflight.AllVolumesMatch,
		Changes:                  scopeChanges(existing, requested),
		NativeIdentities:         make([]NativeIdentity, 0, len(preflight.Matches)),
	}
	if existing != nil {
		out.CurrentConfigSHA256 = digestHex(oldBytes)
	}
	out.RequiresExplicitApproval = len(out.Changes) > 0

	byGUID := make(map[string]volumediscovery.Snapshot, len(native))
	for _, value := range native {
		byGUID[strings.ToLower(value.GUID)] = value
	}
	for _, match := range preflight.Matches {
		identity := NativeIdentity{
			EnrollmentID: match.EnrollmentID,
			VolumeGUID:   match.GUID,
			MatchStatus:  match.Status,
			NativeStatus: "Missing",
		}
		if observed, exists := byGUID[strings.ToLower(match.GUID)]; exists {
			identity.NativeStatus = string(observed.Status)
			identity.NativeSerial64 = observed.Serial64
		}
		out.NativeIdentities = append(out.NativeIdentities, identity)
	}
	// The identity and requested scope order is stable regardless of Windows'
	// enumerator ordering or the order in which config lines were presented.
	sort.Slice(out.NativeIdentities, func(i, j int) bool {
		return out.NativeIdentities[i].EnrollmentID < out.NativeIdentities[j].EnrollmentID
	})
	out.ReviewFingerprintSHA256, err = reviewFingerprint(out)
	if err != nil {
		return Review{}, err
	}
	return out, nil
}

// Revalidate recomputes the exact review against a FRESH native discovery.
// The caller must obtain that discovery immediately before any future
// mutation and must also validate a separate protected approval receipt.
// A successful revalidation alone cannot authorize installation or USN reads.
func Revalidate(previous Review, existing *config.VolumeConfig, requested config.VolumeConfig, freshNative []volumediscovery.Snapshot) error {
	if previous.Version != ReviewVersion || len(previous.ReviewFingerprintSHA256) != 64 {
		return ErrStaleReview
	}
	// The presented review body must still correspond to its fingerprint.
	// This detects accidental/tampered fields, but is NOT a signature; the
	// installer must separately authenticate the approved receipt and file.
	previousFingerprint, err := reviewFingerprint(previous)
	if err != nil || subtle.ConstantTimeCompare(
		[]byte(previous.ReviewFingerprintSHA256),
		[]byte(previousFingerprint),
	) != 1 {
		return ErrStaleReview
	}
	current, err := Build(existing, requested, freshNative)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrStaleReview, err)
	}
	if current.BlocksMutation || !current.AllRequestedVolumesMatch {
		return fmt.Errorf("%w: requested volume identity does not match native discovery", ErrStaleReview)
	}
	if subtle.ConstantTimeCompare(
		[]byte(previous.ReviewFingerprintSHA256),
		[]byte(current.ReviewFingerprintSHA256),
	) != 1 {
		return ErrStaleReview
	}
	return nil
}

func scopeChanges(existing *config.VolumeConfig, requested config.VolumeConfig) []Change {
	oldVolumes := make(map[string]config.VolumeEnrollment)
	oldPolicies := make(map[string]config.RootPolicy)
	if existing != nil {
		for _, value := range existing.Volumes {
			oldVolumes[value.ID] = value
		}
		for _, value := range existing.Policies {
			oldPolicies[value.ID] = value
		}
	}
	newVolumes := make(map[string]config.VolumeEnrollment, len(requested.Volumes))
	newPolicies := make(map[string]config.RootPolicy, len(requested.Policies))
	for _, value := range requested.Volumes {
		newVolumes[value.ID] = value
	}
	for _, value := range requested.Policies {
		newPolicies[value.ID] = value
	}
	changes := make([]Change, 0)
	for id, from := range oldVolumes {
		to, exists := newVolumes[id]
		switch {
		case !exists:
			changes = append(changes, Change{Kind: VolumeRemoved, ID: id, Before: volumeDescription(from)})
		case to != from:
			changes = append(changes, Change{Kind: VolumeIdentityChanged, ID: id, Before: volumeDescription(from), After: volumeDescription(to)})
		}
	}
	for id, to := range newVolumes {
		if _, exists := oldVolumes[id]; !exists {
			changes = append(changes, Change{Kind: VolumeAdded, ID: id, After: volumeDescription(to)})
		}
	}
	for id, from := range oldPolicies {
		to, exists := newPolicies[id]
		switch {
		case !exists:
			changes = append(changes, Change{Kind: PolicyRemoved, ID: id, Before: policyDescription(from)})
		case to != from:
			changes = append(changes, Change{Kind: PolicyChanged, ID: id, Before: policyDescription(from), After: policyDescription(to)})
		}
	}
	for id, to := range newPolicies {
		if _, exists := oldPolicies[id]; !exists {
			changes = append(changes, Change{Kind: PolicyAdded, ID: id, After: policyDescription(to)})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].ID != changes[j].ID {
			return changes[i].ID < changes[j].ID
		}
		return changes[i].Kind < changes[j].Kind
	})
	return changes
}

func volumeDescription(value config.VolumeEnrollment) string {
	return value.GUID + " serial64=" + value.Serial
}

func policyDescription(value config.RootPolicy) string {
	return value.VolumeID + ":" + value.RelativeRoot + " depth=" + string(value.Depth)
}

func digestHex(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}

func reviewFingerprint(value Review) (string, error) {
	// Deliberately exclude ReviewFingerprintSHA256 from its own hash.
	// Stable struct order and sorted slices yield unambiguous bytes with a
	// domain-specific ReviewVersion to prevent cross-protocol digest reuse.
	value.ReviewFingerprintSHA256 = ""
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("serialize volume review fingerprint: %w", err)
	}
	return digestHex(encoded), nil
}
