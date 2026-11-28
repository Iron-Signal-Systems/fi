// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "context"
    "errors"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func testVolumeJournal(scope, serial string) records.USNJournalState {
    return records.USNJournalState{
        ObservedAt: time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
        CollectionMethod: "WindowsNTFSUSNJournalV0",
        ScopeID: scope,
        VolumeIdentity: records.VolumeIdentity{
            MethodVersion: "ntfs-volume/1",
            VolumeGUID: `\\?\Volume{11111111-2222-3333-4444-555555555555}\`,
            VolumeSerial: serial,
        },
        JournalID: "123",
        FirstUSN: "100",
        NextUSN: "900",
        LowestValidUSN: "0",
        MaxUSN: "999999",
        MaximumSize: "4294967296",
        AllocationDelta: "1073741824",
    }
}
func TestServiceCaptureGroupsSeveralRootsOnOneVolume(t *testing.T) {
    roots := []string{`G:\FI-Test`, `G:\Other`, `C:\FI-Governed-Test`}
    query := func(_ context.Context, scope, root string) (records.USNJournalState, error) {
        serial := "1"
        if root == roots[2] { serial = "2" }
        return testVolumeJournal(scope, serial), nil
    }
    groups, err := resolveServiceUSNVolumeCaptures(context.Background(), roots, query)
    if err != nil || len(groups) != 2 ||
        groups[0].RepresentativeRoot != roots[0] ||
        len(groups[0].GovernedRoots) != 2 ||
        groups[0].GovernedRoots[1] != roots[1] ||
        len(groups[1].GovernedRoots) != 1 ||
        groups[0].CaptureScopeID == groups[1].CaptureScopeID {
        t.Fatalf("incorrect deduplicated NTFS volume source plan: %+v %v", groups, err)
    }
}
func TestServiceCaptureRejectsChangedJournalInSameVolume(t *testing.T) {
    calls := 0
    _, err := resolveServiceUSNVolumeCaptures(context.Background(), []string{`G:\a`, `G:\b`},
        func(_ context.Context, scope, _ string) (records.USNJournalState, error) {
            calls++
            state := testVolumeJournal(scope, "1")
            if calls == 2 { state.JournalID = "124" }
            return state, nil
        })
    if err == nil {
        t.Fatal("a changing NTFS journal was silently grouped as continuous")
    }
}
func TestServiceCaptureDiscoveryStopsOnSourceError(t *testing.T) {
    marker := errors.New("USN reader unavailable")
    _, err := resolveServiceUSNVolumeCaptures(context.Background(), []string{`G:\a`},
        func(context.Context, string, string) (records.USNJournalState, error) {
            return records.USNJournalState{}, marker
        })
    if !errors.Is(err, marker) {
        t.Fatalf("source error was suppressed: %v", err)
    }
}
