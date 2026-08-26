// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/supportingstate"
)

func TestSaveSupportingSIDStateMergesCurrentDomainSIDs(t *testing.T) {
	stateDir := t.TempDir()
	old := os.Getenv("FI_STATE_DIR")
	if err := os.Setenv("FI_STATE_DIR", stateDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if old == "" {
			_ = os.Unsetenv("FI_STATE_DIR")
			return
		}
		_ = os.Setenv("FI_STATE_DIR", old)
	})

	identity := records.ProcessIdentityObservation{
		Computer: records.ComputerIdentity{
			NetBIOSName: "SERVER1",
			DNSFQDN:     "server1.iss.local",
			DNSDomain:   "iss.local",
		},
		Token: records.ProcessTokenObservation{
			User: records.TokenPrincipalObservation{
				SID:        "S-1-5-21-1-2-3-1106",
				DomainName: "ISS",
			},
		},
	}

	observed := newObservedSIDSet()
	observed.add("S-1-5-21-1-2-3-1106")
	observed.add("S-1-5-21-1-2-3-2200")
	observed.add("S-1-5-32-544")
	observed.add("S-1-1-0")

	path, count, err := saveSupportingSIDState(identity, observed)
	if err != nil {
		t.Fatal(err)
	}
	if path != filepath.Join(stateDir, supportingstate.DefaultStateFileName) {
		t.Fatalf("path = %q", path)
	}
	if count != 2 {
		t.Fatalf("count = %d, want 2", count)
	}

	state, err := supportingstate.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"S-1-5-21-1-2-3-1106",
		"S-1-5-21-1-2-3-2200",
	}
	if !reflect.DeepEqual(state.RelevantSIDs, want) {
		t.Fatalf("relevant SIDs = %#v, want %#v", state.RelevantSIDs, want)
	}
}

func TestSaveSupportingSIDStateNotApplicableForLocalToken(t *testing.T) {
	identity := records.ProcessIdentityObservation{
		Computer: records.ComputerIdentity{
			NetBIOSName: "SERVER1",
			DNSFQDN:     "server1.iss.local",
			DNSDomain:   "iss.local",
		},
		Token: records.ProcessTokenObservation{
			User: records.TokenPrincipalObservation{
				SID:        "S-1-5-21-9-8-7-1001",
				DomainName: "SERVER1",
			},
		},
	}

	path, count, err := saveSupportingSIDState(identity, newObservedSIDSet())
	if err != nil {
		t.Fatal(err)
	}
	if path != "" || count != 0 {
		t.Fatalf("local token state = (%q, %d), want empty/not-applicable", path, count)
	}
}
