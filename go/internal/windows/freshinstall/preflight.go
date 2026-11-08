// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

// Package freshinstall checks whether a host is eligible for an entirely new,
// volume-first FI installation. It never upgrades, repairs, deletes, adopts,
// or reconciles a previous FI instance. Inspection does not grant consent to
// enroll any volume or permission to perform installer mutations.
package freshinstall

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Current FI service names are fixed by the Windows SCM contract. The same
// names will be retained during the volume-first redesign, but the existing
// services must be completely absent before any future fresh v2 install.
var serviceNames = [...]string{
	"FICollector",
	"FIUSNReader",
	"FIObjReader",
	"FICRLRefresher",
	"FISender",
}

// FI-owned directories. Any existing directory, file, symlink or reparse
// point at these roots means this is not a clean installation. Read-only
// inspection must never erase custody, PKI, logs or previous state.
var ownedPaths = [...]string{
	`C:\Program Files\FI`,
	`C:\ProgramData\FI`,
}

type Presence string

const (
	Absent  Presence = "Absent"
	Present Presence = "Present"
	Unknown Presence = "Unknown"
)

type Kind string

const (
	Service Kind = "Service"
	Path    Kind = "Path"
)

type Finding struct {
	Kind     Kind     `json:"kind"`
	Target   string   `json:"target"`
	Presence Presence `json:"presence"`
	Detail   string   `json:"detail,omitempty"`
}

type Report struct {
	Version       string    `json:"version"`
	Mode          string    `json:"mode"`
	Clean         bool      `json:"clean"`
	InstallBlocked bool     `json:"install_blocked"`
	Findings      []Finding `json:"findings"`
}

const (
	ReportVersion = "fi-windows-v2-fresh-preflight/1"
	InstallMode   = "FreshInstallOnly"
)

var ErrExistingFI = errors.New("FI fresh installation blocked: existing or unverified local FI artifacts")

// Inspector must inspect fixed names read-only. It must report access denied,
// ambiguous discovery, and unexpected native errors as Unknown (not Absent).
type Inspector interface {
	Service(name string) (Presence, error)
	Path(path string) (Presence, error)
}

// Assess always checks every known local FI artifact and reports all findings.
// A stale result is not a reusable installation approval: the future installer
// must execute the native check again immediately before EACH write boundary.
func Assess(inspector Inspector) (Report, error) {
	if inspector == nil {
		return Report{}, errors.New("FI fresh-install inspector is required")
	}
	report := Report{
		Version:        ReportVersion,
		Mode:           InstallMode,
		Clean:          true,
		InstallBlocked: false,
		Findings:       make([]Finding, 0, len(serviceNames)+len(ownedPaths)),
	}
	for _, name := range serviceNames {
		presence, err := inspector.Service(name)
		report.Findings = append(report.Findings,
			summarize(Service, name, presence, err))
	}
	for _, path := range ownedPaths {
		presence, err := inspector.Path(path)
		report.Findings = append(report.Findings,
			summarize(Path, path, presence, err))
	}
	// Stable ordering is important for deterministic installer review output.
	sort.Slice(report.Findings, func(i, j int) bool {
		if report.Findings[i].Kind != report.Findings[j].Kind {
			return report.Findings[i].Kind < report.Findings[j].Kind
		}
		return strings.ToLower(report.Findings[i].Target) < strings.ToLower(report.Findings[j].Target)
	})
	for _, finding := range report.Findings {
		if finding.Presence != Absent {
			report.Clean = false
			report.InstallBlocked = true
		}
	}
	if report.InstallBlocked {
		return report, ErrExistingFI
	}
	return report, nil
}

func summarize(kind Kind, target string, presence Presence, checkErr error) Finding {
	out := Finding{Kind: kind, Target: target, Presence: presence}
	if checkErr != nil {
		out.Presence = Unknown
		out.Detail = checkErr.Error()
		return out
	}
	switch presence {
	case Absent:
		return out
	case Present:
		out.Detail = "existing FI installation artifact; manual disposition required"
	case Unknown:
		out.Detail = "native inspection could not prove absence"
	default:
		out.Presence = Unknown
		out.Detail = fmt.Sprintf("invalid native presence status %q", presence)
	}
	return out
}
