// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

func TestWriteBaselineRootStreamsObjectsBeforeDirectoryResolution(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "sample.txt"), []byte("sample"), 0o600); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := writeBaselineRoot(context.Background(), &output, root); err != nil {
		t.Fatal(err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(output.Bytes()))
	events := []baselineEvent{}
	for scanner.Scan() {
		var event baselineEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatalf("decode baseline line: %v\n%s", err, scanner.Text())
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	if len(events) < 5 {
		t.Fatalf("baseline emitted %d events, want at least 5", len(events))
	}

	if events[0].Kind != baselineKindCollectorIdentity || events[0].CollectorIdentity == nil {
		t.Fatalf("first event = %+v, want collector identity", events[0])
	}

	if events[1].Kind != baselineKindSMBShareSnapshot {
		t.Fatalf("second event kind = %q, want %q", events[1].Kind, baselineKindSMBShareSnapshot)
	}
	if events[1].SMBShareSnapshot == nil && events[1].Error == "" {
		t.Fatal("SMB share event contains neither snapshot nor explicit error")
	}

	if events[2].Kind != baselineKindLocalPrincipals {
		t.Fatalf("third event kind = %q, want %q", events[2].Kind, baselineKindLocalPrincipals)
	}
	if events[2].LocalPrincipals == nil && events[2].Error == "" {
		t.Fatal("local principal event contains neither snapshot nor explicit error")
	}

	last := events[len(events)-1]
	if last.Kind != baselineKindDirectoryPrincipals {
		t.Fatalf("last event kind = %q, want %q", last.Kind, baselineKindDirectoryPrincipals)
	}
	if last.DirectoryPrincipals == nil && last.Error == "" {
		t.Fatal("directory principal event contains neither snapshot nor explicit error")
	}

	foundObject := false
	for _, event := range events[3 : len(events)-1] {
		if event.Kind != baselineKindNTFSObservation {
			t.Fatalf("unexpected event kind %q between baseline context and directory resolution", event.Kind)
		}
		if event.PathDisplay == "" || event.PathUTF16LEBase64URL == "" {
			t.Fatalf("NTFS event missing path identity: %+v", event)
		}
		if event.Observation != nil {
			foundObject = true
		}
	}
	if !foundObject {
		t.Fatal("baseline emitted no successful NTFS observations")
	}
}

func TestAddNTFSObservationSIDsIncludesSecurityAndSACL(t *testing.T) {
	set := newObservedSIDSet()
	observation := ntfs.Observation{
		Security: records.SecurityObservation{
			OwnerSID:        "S-1-5-21-1-2-3-1106",
			PrimaryGroupSID: "S-1-5-21-1-2-3-513",
			DACL: records.ACLObservation{ACEs: []records.ACEObservation{
				{SID: "S-1-5-21-1-2-3-2100"},
				{SID: "S-1-1-0"},
			}},
		},
		SACL: records.SACLObservation{
			ACL: records.ACLObservation{ACEs: []records.ACEObservation{
				{SID: "S-1-5-21-1-2-3-2200"},
			}},
		},
	}

	addNTFSObservationSIDs(set, observation)
	for _, sid := range []string{
		"S-1-5-21-1-2-3-1106",
		"S-1-5-21-1-2-3-513",
		"S-1-5-21-1-2-3-2100",
		"S-1-1-0",
		"S-1-5-21-1-2-3-2200",
	} {
		if _, ok := set.values[sid]; !ok {
			t.Fatalf("SID %s was not gathered", sid)
		}
	}
}

func TestCurrentDomainObservedSIDsFiltersOtherSIDNamespaces(t *testing.T) {
	identity := records.ProcessIdentityObservation{
		Computer: records.ComputerIdentity{NetBIOSName: "SERVER1", DNSDomain: "iss.local"},
		Token: records.ProcessTokenObservation{
			User: records.TokenPrincipalObservation{
				SID:        "S-1-5-21-1-2-3-1106",
				DomainName: "ISS",
			},
		},
	}
	observed := map[string]struct{}{
		"S-1-5-21-1-2-3-1106": {},
		"S-1-5-21-1-2-3-2100": {},
		"S-1-5-21-9-8-7-2100": {},
		"S-1-5-32-544":        {},
		"S-1-1-0":             {},
	}

	got := currentDomainObservedSIDs(identity, observed)
	want := []string{
		"S-1-5-21-1-2-3-1106",
		"S-1-5-21-1-2-3-2100",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}
