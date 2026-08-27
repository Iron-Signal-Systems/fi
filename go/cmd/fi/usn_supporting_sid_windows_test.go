// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/supportingstate"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/usn"
)

func TestMergeSupportingSIDStateOnlyWritesNewSIDs(t *testing.T) {
	stateDir := t.TempDir()
	oldState := os.Getenv("FI_STATE_DIR")
	if err := os.Setenv("FI_STATE_DIR", stateDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if oldState == "" {
			_ = os.Unsetenv("FI_STATE_DIR")
			return
		}
		_ = os.Setenv("FI_STATE_DIR", oldState)
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

	first := newObservedSIDSet()
	first.add("S-1-5-21-1-2-3-1106")
	first.add("S-1-1-0")

	result, err := mergeSupportingSIDState(identity, first)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Updated || result.CountBefore != 0 || result.CountAfter != 1 {
		t.Fatalf("first merge = %#v", result)
	}
	if result.Path != filepath.Join(
		stateDir,
		supportingstate.DefaultStateFileName,
	) {
		t.Fatalf("state path = %q", result.Path)
	}

	result, err = mergeSupportingSIDState(identity, first)
	if err != nil {
		t.Fatal(err)
	}
	if result.Updated || result.CountBefore != 1 || result.CountAfter != 1 {
		t.Fatalf("unchanged merge = %#v", result)
	}

	second := newObservedSIDSet()
	second.add("S-1-5-21-1-2-3-2200")

	result, err = mergeSupportingSIDState(identity, second)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Updated || result.CountBefore != 1 || result.CountAfter != 2 {
		t.Fatalf("second merge = %#v", result)
	}
}

func TestMergeUSNObservedSIDsIgnoresUnavailableObservation(t *testing.T) {
	selected := []selectedUSNObject{
		{
			Reobservation: usn.ChangeReobservation{
				Status: usn.ReobservationUnavailable,
				Observation: &ntfs.Observation{
					Security: records.SecurityObservation{
						OwnerSID: "S-1-5-21-1-2-3-9999",
					},
				},
			},
		},
	}

	observed := newObservedSIDSet()
	for _, selection := range selected {
		reobservation := selection.Reobservation
		if reobservation.Status != usn.ReobservationObserved ||
			reobservation.Observation == nil {
			continue
		}
		addNTFSObservationSIDs(observed, *reobservation.Observation)
	}
	if len(observed.values) != 0 {
		t.Fatalf("unavailable observation contributed SIDs: %#v", observed.values)
	}
}

func TestUSNObservedSIDExtractionIncludesOwnerDACLAndSACL(t *testing.T) {
	observation := ntfs.Observation{
		Security: records.SecurityObservation{
			OwnerSID:        "S-1-5-21-1-2-3-1100",
			PrimaryGroupSID: "S-1-5-21-1-2-3-513",
			DACL: records.ACLObservation{
				ACEs: []records.ACEObservation{
					{SID: "S-1-5-21-1-2-3-2200"},
				},
			},
		},
		SACL: records.SACLObservation{
			ACL: records.ACLObservation{
				ACEs: []records.ACEObservation{
					{SID: "S-1-5-21-1-2-3-3300"},
				},
			},
		},
	}

	set := newObservedSIDSet()
	addNTFSObservationSIDs(set, observation)

	for _, sid := range []string{
		"S-1-5-21-1-2-3-1100",
		"S-1-5-21-1-2-3-513",
		"S-1-5-21-1-2-3-2200",
		"S-1-5-21-1-2-3-3300",
	} {
		if _, exists := set.values[sid]; !exists {
			t.Fatalf("missing SID %s", sid)
		}
	}
}
