// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usnbroker

import (
	"errors"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumediscovery"
)

// enrolledVolumeTarget is an approved selection, never a client-provided raw
// device path. The privileged raw-volume layer must independently re-attest
// this identity against the opened native handle before each USN operation.
type enrolledVolumeTarget struct {
	EnrollmentID string
	VolumeGUID   string
	Serial64     string
}

// volumeAuthoritySnapshot is immutable after FIUSNReader startup. Changes to
// the requested configuration or discovery slice cannot broaden its rights.
// Offline, replaced, or unsupported requested volumes are denied individually
// so one failure does not disable unrelated approved volumes.
type volumeAuthoritySnapshot struct {
	allowed map[string]enrolledVolumeTarget
	blocked map[string]volumediscovery.MatchStatus
}

// newVolumeAuthoritySnapshot binds trusted on-disk configuration to an
// independently collected native snapshot. A matching native volume identity
// is necessary but NOT sufficient to authorize I/O: separate operator approval,
// FICollector service-SID authentication and on-handle native re-attestation
// remain mandatory.
func newVolumeAuthoritySnapshot(
	approved config.VolumeConfig,
	native []volumediscovery.Snapshot,
) (volumeAuthoritySnapshot, error) {
	if len(native) == 0 {
		return volumeAuthoritySnapshot{}, errors.New("FI USN volume authority requires native discovery")
	}
	// This validation re-parses the exact v2 declaration and rejects invalid
	// model mutations; it does not mistake an arbitrary in-memory struct for
	// an installed/approved configuration.
	if _, err := config.CanonicalVolumeV2(approved); err != nil {
		return volumeAuthoritySnapshot{}, fmt.Errorf("invalid FI volume authority configuration: %w", err)
	}
	preflight, err := volumediscovery.AssessEnrollment(approved, native)
	if err != nil {
		return volumeAuthoritySnapshot{}, fmt.Errorf("FI USN volume authorization discovery failed: %w", err)
	}
	if len(preflight.Matches) != len(approved.Volumes) {
		return volumeAuthoritySnapshot{}, errors.New("FI volume authorization preflight is incomplete")
	}
	enrollments := make(map[string]config.VolumeEnrollment, len(approved.Volumes))
	for _, item := range approved.Volumes {
		enrollments[item.ID] = item
	}
	authority := volumeAuthoritySnapshot{
		allowed: make(map[string]enrolledVolumeTarget, len(approved.Volumes)),
		blocked: make(map[string]volumediscovery.MatchStatus),
	}
	for _, match := range preflight.Matches {
		target, exists := enrollments[match.EnrollmentID]
		if !exists {
			return volumeAuthoritySnapshot{}, fmt.Errorf("unknown FI preflight enrollment %q", match.EnrollmentID)
		}
		if match.Status != volumediscovery.IdentityMatched {
			authority.blocked[match.EnrollmentID] = match.Status
			continue
		}
		authority.allowed[match.EnrollmentID] = enrolledVolumeTarget{
			EnrollmentID: target.ID,
			VolumeGUID:   target.GUID,
			Serial64:     target.Serial,
		}
	}
	return authority, nil
}

// resolve is the only selection interface exposed to the broker dispatcher.
// The request contains only an enrollment ID. It cannot supply a GUID, drive
// letter or raw device path that could bypass approved configuration.
func (snapshot volumeAuthoritySnapshot) resolve(enrollmentID string) (enrolledVolumeTarget, error) {
	if !validVolumeEnrollmentID(enrollmentID) {
		return enrolledVolumeTarget{}, errors.New("invalid FI volume enrollment ID")
	}
	if target, exists := snapshot.allowed[enrollmentID]; exists {
		return target, nil
	}
	if status, exists := snapshot.blocked[enrollmentID]; exists {
		return enrolledVolumeTarget{}, fmt.Errorf(
			"FI enrollment %q is not available for USN access: %s", enrollmentID, status,
		)
	}
	return enrolledVolumeTarget{}, fmt.Errorf("FI enrollment %q was not approved for USN access", enrollmentID)
}

// Stable IDs are deliberately narrow: in addition to validating the wire
// contract, this prevents traversal and casing ambiguity if future state files
// use the ID as a filename component.
func validVolumeEnrollmentID(id string) bool {
	if len(id) == 0 || len(id) > 64 || id[0] < 'a' || id[0] > 'z' {
		return false
	}
	for i := 1; i < len(id); i++ {
		c := id[i]
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
