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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumediscovery"
)

const inventoryDataGUID = `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`

func inventoryFlagSet(t *testing.T, args ...string) *flag.FlagSet {
	t.Helper()
	set := flag.NewFlagSet("fi-install", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	set.Bool("list-volumes", false, "")
	set.Bool("apply", true, "")
	set.Bool("plan-only", false, "")
	set.String("config", "", "")
	set.String("volume-config", "", "")
	if err := set.Parse(args); err != nil {
		t.Fatal(err)
	}
	return set
}

func TestStandaloneVolumeInventoryFlags(t *testing.T) {
	for _, args := range [][]string{
		{"-list-volumes"},
		{"-list-volumes", "-volume-config=C:\\FI\\scope.conf"},
	} {
		if err := volumeInventoryCLI(inventoryFlagSet(t, args...)); err != nil {
			t.Fatalf("valid read-only arguments %v rejected: %v", args, err)
		}
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

func validInventoryScope(t *testing.T) config.VolumeConfig {
	t.Helper()
	raw := `version_id: 2.0
volume.data.guid = \\?\Volume{18fed846-4275-4251-b698-f268192100f2}\
volume.data.serial = 15172277115761558407
`
	value, err := config.ParseVolumeV2(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func healthyInventory(context.Context) ([]volumediscovery.Snapshot, error) {
	return []volumediscovery.Snapshot{
		{GUID: inventoryDataGUID, Serial64: "15172277115761558407", FileSystem: "NTFS", Status: volumediscovery.Eligible},
	}, nil
}

func TestVolumeInventoryDoesNotAuthorizeCollection(t *testing.T) {
	var output bytes.Buffer
	timeOfTest := time.Date(2026, time.November, 8, 15, 0, 0, 0, time.UTC)
	calls := 0
	err := writeVolumeInventory(
		context.Background(), &output,
		func(ctx context.Context) ([]volumediscovery.Snapshot, error) {
			calls++
			return healthyInventory(ctx)
		},
		func() time.Time { return timeOfTest },
		nil,
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
		report.CollectionAuthorized || report.RequestedVolumePreflight != nil ||
		report.ObservedAtUTC != "2026-11-08T15:00:00Z" ||
		len(report.Volumes) != 1 || report.Volumes[0].Status != volumediscovery.Eligible {
		t.Fatalf("unsafe/malformed read-only report: %+v", report)
	}
}

func TestVolumeInventoryPreflightReadOnly(t *testing.T) {
	requested := validInventoryScope(t)
	var output bytes.Buffer
	if err := writeVolumeInventory(context.Background(), &output, healthyInventory, time.Now, &requested); err != nil {
		t.Fatal(err)
	}
	var report volumeInventoryReport
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.CollectionAuthorized || report.Action != "DiscoveryAndScopePreflightOnly" ||
		len(report.RequestedConfigSHA256) != 64 || report.RequestedVolumePreflight == nil ||
		!report.RequestedVolumePreflight.AllVolumesMatch ||
		!report.RequestedVolumePreflight.ObservationOnly ||
		report.RequestedScopeReview == nil ||
		!report.RequestedScopeReview.RequiresExplicitApproval ||
		report.RequestedScopeReview.BlocksMutation ||
		len(report.RequestedScopeReview.Changes) != 1 ||
		report.RequestedScopeReview.RequestedConfigSHA256 != report.RequestedConfigSHA256 ||
		len(report.RequestedScopeReview.ReviewFingerprintSHA256) != 64 {
		t.Fatalf("unsafe/malformed preflight: %+v", report)
	}
}

func TestVolumeInventoryMismatchReturnsErrorAndEvidence(t *testing.T) {
	requested := validInventoryScope(t)
	var output bytes.Buffer
	err := writeVolumeInventory(context.Background(), &output,
		func(context.Context) ([]volumediscovery.Snapshot, error) {
			return []volumediscovery.Snapshot{
				{GUID: inventoryDataGUID, Serial64: "15172277115761558408", FileSystem: "NTFS", Status: volumediscovery.Eligible},
			}, nil
		}, time.Now, &requested)
	if !errors.Is(err, ErrVolumePreflightMismatch) {
		t.Fatalf("mismatch did not block scope: %v", err)
	}
	var report volumeInventoryReport
	if json.Unmarshal(output.Bytes(), &report) != nil || report.RequestedVolumePreflight == nil ||
		report.RequestedVolumePreflight.AllVolumesMatch || report.CollectionAuthorized ||
		report.RequestedScopeReview == nil ||
		!report.RequestedScopeReview.BlocksMutation ||
		report.RequestedScopeReview.AllRequestedVolumesMatch {
		t.Fatalf("mismatch report concealed drift: %+v", report)
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
			err := writeVolumeInventory(context.Background(), &output, tc.discover, time.Now, nil)
			if err == nil || output.Len() != 0 {
				t.Fatalf("returned error=%v, report=%q", err, output.String())
			}
		})
	}
	err := writeVolumeInventory(context.Background(), unavailableOutput{},
		healthyInventory, time.Now, nil)
	if err == nil || !strings.Contains(err.Error(), "write read-only") {
		t.Fatalf("missing output failure: %v", err)
	}
	if err := writeVolumeInventory(nil, io.Discard, healthyInventory, time.Now, nil); err == nil {
		t.Fatal("nil context accepted")
	}
	invalid := validInventoryScope(t)
	invalid.Volumes[0].ID = "../traversal"
	calls := 0
	var output bytes.Buffer
	err = writeVolumeInventory(context.Background(), &output,
		func(ctx context.Context) ([]volumediscovery.Snapshot, error) {
			calls++
			return healthyInventory(ctx)
		}, time.Now, &invalid)
	if err == nil || calls != 0 || output.Len() != 0 {
		t.Fatalf("invalid approval scope caused enumeration: error=%v calls=%d", err, calls)
	}
}

func TestLoadVolumeDeclarationBoundedAndStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "volume.conf")
	raw := `version_id: 2.0
volume.data.guid = \\?\Volume{18fed846-4275-4251-b698-f268192100f2}\
volume.data.serial = 15172277115761558407
`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	value, err := loadVolumeDeclaration(path)
	if err != nil || len(value.Volumes) != 1 {
		t.Fatalf("valid declaration rejected: %+v %v", value, err)
	}
	if err := os.WriteFile(path, []byte("version_id: 1.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVolumeDeclaration(path); err == nil {
		t.Fatal("old root-centric configuration was accepted")
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{'a'}, maxVolumeDeclarationBytes+1), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadVolumeDeclaration(path); err == nil {
		t.Fatal("oversized scope configuration accepted")
	}
	if _, err := loadVolumeDeclaration(t.TempDir()); err == nil {
		t.Fatal("directory used as scope configuration")
	}
}
