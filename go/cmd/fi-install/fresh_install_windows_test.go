// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/freshinstall"
)

type fakeFreshInspector struct {
	servicePresence freshinstall.Presence
	pathPresence freshinstall.Presence
	serviceError error
	pathError error
}

func (p fakeFreshInspector) Service(string) (freshinstall.Presence, error) {
	if p.serviceError != nil {
		return freshinstall.Unknown, p.serviceError
	}
	if p.servicePresence == "" {
		return freshinstall.Absent, nil
	}
	return p.servicePresence, nil
}

func (p fakeFreshInspector) Path(string) (freshinstall.Presence, error) {
	if p.pathError != nil {
		return freshinstall.Unknown, p.pathError
	}
	if p.pathPresence == "" {
		return freshinstall.Absent, nil
	}
	return p.pathPresence, nil
}

func freshFlags(t *testing.T, args ...string) *flag.FlagSet {
	t.Helper()
	flags := flag.NewFlagSet("fi-install", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Bool("check-clean-install", false, "")
	flags.Bool("list-volumes", false, "")
	flags.String("volume-config", "", "")
	flags.Bool("apply", true, "")
	flags.Bool("plan-only", false, "")
	flags.String("config", "", "")
	if err := flags.Parse(args); err != nil {
		t.Fatal(err)
	}
	return flags
}

func TestFreshInstallStandaloneFlagsCannotReachLegacyApply(t *testing.T) {
	if err := freshInstallCLI(freshFlags(t, "-check-clean-install")); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-check-clean-install", "-apply"},
		{"-check-clean-install", "-apply=false"},
		{"-check-clean-install", "-plan-only"},
		{"-check-clean-install", "-list-volumes"},
		{"-check-clean-install", "-volume-config=C:\\FI-v2.conf"},
		{"-check-clean-install", "-config=C:\\FI-v1.conf"},
		{"-check-clean-install", "ignored-file"},
	} {
		if err := freshInstallCLI(freshFlags(t, args...)); err == nil {
			t.Fatalf("accepted unsafe mixed installer flags: %v", args)
		}
	}
	if err := freshInstallCLI(nil); err == nil {
		t.Fatal("nil flag set accepted")
	}
}

func TestFreshInstallJSONNeverClaimsInstallationAuthority(t *testing.T) {
	var out bytes.Buffer
	if err := writeFreshInstallPreflight(&out, fakeFreshInspector{}); err != nil {
		t.Fatal(err)
	}
	var result freshinstall.Report
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Clean || result.InstallBlocked ||
		result.Mode != freshinstall.InstallMode ||
		result.Version != freshinstall.ReportVersion ||
		len(result.Findings) != 7 {
		t.Fatalf("incorrect clean read-only preflight: %+v", result)
	}
}

func TestFreshInstallJSONReportsResidueAndReturnsNonzeroError(t *testing.T) {
	var out bytes.Buffer
	err := writeFreshInstallPreflight(&out, fakeFreshInspector{
		servicePresence: freshinstall.Present,
		pathPresence: freshinstall.Present,
	})
	if !errors.Is(err, freshinstall.ErrExistingFI) {
		t.Fatalf("existing FI did not block: %v", err)
	}
	var result freshinstall.Report
	if json.Unmarshal(out.Bytes(), &result) != nil || result.Clean ||
		!result.InstallBlocked || len(result.Findings) != 7 {
		t.Fatalf("existing FI hidden in report: %+v", result)
	}
}

func TestFreshInstallJSONBlocksNativeUncertainty(t *testing.T) {
	var out bytes.Buffer
	err := writeFreshInstallPreflight(&out, fakeFreshInspector{
		serviceError: errors.New("access denied"),
	})
	if !errors.Is(err, freshinstall.ErrExistingFI) {
		t.Fatalf("SCM ambiguity did not block: %v", err)
	}
	if !strings.Contains(out.String(), `"presence": "Unknown"`) {
		t.Fatalf("unknown SCM state was suppressed: %s", out.String())
	}
	if err := writeFreshInstallPreflight(nil, fakeFreshInspector{}); err == nil {
		t.Fatal("nil output accepted")
	}
}
