// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumediscovery"
)

func inventoryFlagSet(t *testing.T, args ...string) *flag.FlagSet {
	t.Helper()
	set := flag.NewFlagSet("fi-install", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.Bool("list-volumes", false, "")
	set.Bool("apply", true, "")
	set.Bool("plan-only", false, "")
	set.String("config", "", "")
	if err := set.Parse(args); err != nil {
		t.Fatal(err)
	}
	return set
}

func TestStandaloneVolumeInventoryFlags(t *testing.T) {
	if err := volumeInventoryCLI(inventoryFlagSet(t, "-list-volumes")); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-list-volumes", "-apply=true"},
		{"-list-volumes", "-apply=false"},
		{"-list-volumes", "-plan-only"},
		{"-list-volumes", "-config=C:\\FI\\fi.conf"},
		{"-list-volumes", "unexpected"},
	} {
		if err := volumeInventoryCLI(inventoryFlagSet(t, args...)); err == nil {
			t.Fatalf("inventory accepted conflicting flags %v", args)
		}
	}
	if err := volumeInventoryCLI(nil); err == nil {
		t.Fatal("nil flag set accepted")
	}
}

func TestVolumeInventoryDoesNotAuthorizeCollection(t *testing.T) {
	var output bytes.Buffer
	timeOfTest := time.Date(2026, time.November, 8, 15, 0, 0, 0, time.UTC)
	calls := 0
	err := writeVolumeInventory(
		context.Background(),
		&output,
		func(context.Context) ([]volumediscovery.Snapshot, error) {
			calls++
			return []volumediscovery.Snapshot{
				{
					GUID:       `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`,
					Serial64:   "15172277115761558407",
					FileSystem: "NTFS",
					Status:     volumediscovery.Eligible,
				},
			}, nil
		},
		func() time.Time { return timeOfTest },
	)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("discovery called %d times, expected exactly one", calls)
	}
	var report volumeInventoryReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Version != volumeDiscoveryReportVersion || report.Action != "DiscoveryOnly" ||
		report.CollectionAuthorized || report.ObservedAtUTC != "2026-11-08T15:00:00Z" ||
		len(report.Volumes) != 1 || report.Volumes[0].Status != volumediscovery.Eligible {
		t.Fatalf("unsafe/malformed read-only discovery report: %+v", report)
	}
}

type unavailableOutput struct{}

func (unavailableOutput) Write([]byte) (int, error) { return 0, errors.New("output failed") }

func TestVolumeInventoryFailurePathsDoNotReportSuccess(t *testing.T) {
	sourceErr := errors.New("native enumeration failed")
	tests := []struct {
		name     string
		discover func(context.Context) ([]volumediscovery.Snapshot, error)
	}{
		{"failure", func(context.Context) ([]volumediscovery.Snapshot, error) { return nil, sourceErr }},
		{"empty result", func(context.Context) ([]volumediscovery.Snapshot, error) { return nil, nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			err := writeVolumeInventory(context.Background(), &output, tc.discover, time.Now)
			if err == nil || output.Len() != 0 {
				t.Fatalf("returned error=%v, report=%q", err, output.String())
			}
		})
	}
	err := writeVolumeInventory(context.Background(), unavailableOutput{},
		func(context.Context) ([]volumediscovery.Snapshot, error) {
			return []volumediscovery.Snapshot{{GUID: `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`, Status: volumediscovery.Unavailable, Detail: "offline"}}, nil
		}, time.Now)
	if err == nil || !strings.Contains(err.Error(), "write read-only") {
		t.Fatalf("missing output failure: %v", err)
	}
	if err := writeVolumeInventory(nil, io.Discard, func(context.Context) ([]volumediscovery.Snapshot, error) {
		return nil, nil
	}, time.Now); err == nil {
		t.Fatal("nil context accepted")
	}
}
