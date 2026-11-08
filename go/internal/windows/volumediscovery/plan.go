// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package volumediscovery isolates read-only Windows NTFS volume discovery
// from authorization. Neither an observed device nor a successful match grants
// FICollector, FIUSNReader, or the installer permission to open the volume.
package volumediscovery

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
)

// Status describes what native read-only discovery established about a volume.
// Missing volumes are assessed at the enrollment layer, not fabricated as
// members of a native discovery snapshot.
type Status string

const (
	Eligible    Status = "Eligible"
	Unsupported Status = "Unsupported"
	Unavailable Status = "Unavailable"
)

// Snapshot contains only facts from the current local Windows host. MountPaths
// are informational aliases, never the authorization identity of a volume.
// Serial64 is FILE_ID_INFO.VolumeSerialNumber, not GetVolumeInformationW's
// truncated 32-bit serial.
type Snapshot struct {
	GUID           string
	Serial64       string
	FileSystem     string
	MountPaths     []string
	MountPathError string // informational; never an enrollment/identity input
	Status         Status
	Detail         string
}

// MatchStatus describes an enrollment's read-only preflight result.
type MatchStatus string

const (
	IdentityMatched MatchStatus = "IdentityMatched"
	NotDiscovered   MatchStatus = "NotDiscovered"
	NotEligible     MatchStatus = "NotEligible"
	IdentityChanged MatchStatus = "IdentityChanged"
)

// Match is a report, not an authorization token. Operator approval and fresh
// native rediscovery remain mandatory before any runtime or installer action.
type Match struct {
	EnrollmentID string
	GUID         string
	Status       MatchStatus
	Detail       string
}

// Preflight deliberately has no "Approved" field. All policy roots still need
// separate native object-identity/reparse verification and consent.
type Preflight struct {
	Matches          []Match
	Unenrolled       []Snapshot
	AllVolumesMatch  bool
	PolicyCount      int
	ObservationOnly  bool
}

// AssessEnrollment compares a canonical requested configuration with a
// complete native discovery snapshot. A discovered volume is never enrolled
// implicitly, and any requested mismatch blocks the preflight as a whole.
// This is not a plan to mutate services, permissions, audit policy, or files.
func AssessEnrollment(request config.VolumeConfig, discovered []Snapshot) (Preflight, error) {
	if _, err := config.CanonicalVolumeV2(request); err != nil {
		return Preflight{}, fmt.Errorf("invalid volume enrollment declaration: %w", err)
	}
	index := make(map[string]Snapshot, len(discovered))
	for _, item := range discovered {
		guid, err := canonicalGUID(item.GUID)
		if err != nil {
			return Preflight{}, fmt.Errorf("malformed native discovery GUID %q: %w", item.GUID, err)
		}
		if _, exists := index[guid]; exists {
			return Preflight{}, fmt.Errorf("duplicate native discovery volume %q", guid)
		}
		switch item.Status {
		case Eligible:
			if item.FileSystem != "NTFS" || item.Detail != "" {
				return Preflight{}, fmt.Errorf("volume %q claimed Eligible with inconsistent filesystem/detail", guid)
			}
			if err := validSerial(item.Serial64); err != nil {
				return Preflight{}, fmt.Errorf("volume %q has invalid FILE_ID_INFO serial: %w", guid, err)
			}
		case Unsupported:
			if item.Detail == "" || strings.EqualFold(item.FileSystem, "NTFS") {
				return Preflight{}, fmt.Errorf("volume %q claimed Unsupported without valid reason", guid)
			}
		case Unavailable:
			if item.Detail == "" {
				return Preflight{}, fmt.Errorf("volume %q claimed Unavailable without reason", guid)
			}
		default:
			return Preflight{}, fmt.Errorf("volume %q has unknown discovery status %q", guid, item.Status)
		}
		item.GUID = guid
		index[guid] = item
	}

	out := Preflight{
		Matches:         make([]Match, 0, len(request.Volumes)),
		Unenrolled:      make([]Snapshot, 0),
		AllVolumesMatch: true,
		PolicyCount:     len(request.Policies),
		ObservationOnly: true,
	}
	requested := make(map[string]struct{}, len(request.Volumes))
	for _, enrolled := range request.Volumes {
		guid, _ := canonicalGUID(enrolled.GUID) // validated by CanonicalVolumeV2
		requested[guid] = struct{}{}
		report := Match{EnrollmentID: enrolled.ID, GUID: guid}
		item, found := index[guid]
		switch {
		case !found:
			report.Status = NotDiscovered
			report.Detail = "enrolled volume is absent from the current native snapshot"
		case item.Status != Eligible:
			report.Status = NotEligible
			report.Detail = string(item.Status) + ": " + item.Detail
		case item.Serial64 != enrolled.Serial:
			report.Status = IdentityChanged
			report.Detail = "current full-width NTFS serial does not match approved declaration"
		default:
			report.Status = IdentityMatched
		}
		if report.Status != IdentityMatched {
			out.AllVolumesMatch = false
		}
		out.Matches = append(out.Matches, report)
	}
	for guid, item := range index {
		if _, exists := requested[guid]; !exists {
			out.Unenrolled = append(out.Unenrolled, item)
		}
	}
	sort.Slice(out.Unenrolled, func(i, j int) bool {
		return out.Unenrolled[i].GUID < out.Unenrolled[j].GUID
	})
	return out, nil
}

// canonicalGUID deliberately validates Windows volume-GUID syntax independently
// of a mount path. Go's EqualFold is used only for the Volume prefix; native
// GUID digits must be exactly hex with the expected separator positions.
func canonicalGUID(value string) (string, error) {
	const prefix = `\\?\Volume{`
	const suffix = `}\`
	if len(value) != len(prefix)+36+len(suffix) || !strings.EqualFold(value[:min(len(prefix), len(value))], prefix) || !strings.HasSuffix(value, suffix) {
		return "", errors.New("expected a Windows volume GUID path")
	}
	id := value[len(prefix) : len(prefix)+36]
	for i := 0; i < 36; i++ {
		c := id[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return "", errors.New("invalid GUID separator")
			}
			continue
		}
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return "", errors.New("invalid GUID hex digit")
		}
	}
	return prefix + strings.ToLower(id) + suffix, nil
}

func validSerial(value string) error {
	if value == "" || value[0] < '1' || value[0] > '9' {
		return errors.New("serial must be nonzero canonical unsigned decimal")
	}
	for i := 1; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return errors.New("serial must be canonical unsigned decimal")
		}
	}
	if _, err := strconv.ParseUint(value, 10, 64); err != nil {
		return fmt.Errorf("serial exceeds uint64: %w", err)
	}
	return nil
}
