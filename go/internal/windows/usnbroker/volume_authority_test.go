// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usnbroker

import (
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumediscovery"
)

const (
	volumeDataGUID   = `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`
	volumeSystemGUID = `\\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\`
)

func approvedVolumeFixture(t *testing.T) config.VolumeConfig {
	t.Helper()
	input := `version_id: 2.0
volume.data.guid = \\?\Volume{18fed846-4275-4251-b698-f268192100f2}\
volume.data.serial = 15172277115761558407
volume.system.guid = \\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\
volume.system.serial = 14888954410052949637
policy.finance.volume = data
policy.finance.root = \Shares\Finance
policy.finance.depth = security
`
	value, err := config.ParseVolumeV2(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func volumeDiscoveryFixture() []volumediscovery.Snapshot {
	return []volumediscovery.Snapshot{
		{GUID: volumeDataGUID, Serial64: "15172277115761558407", FileSystem: "NTFS", Status: volumediscovery.Eligible},
		{GUID: volumeSystemGUID, Serial64: "14888954410052949637", FileSystem: "NTFS", Status: volumediscovery.Eligible},
	}
}

func TestApprovedVolumeAuthoritySelectsNativeTargets(t *testing.T) {
	approved := approvedVolumeFixture(t)
	found := volumeDiscoveryFixture()
	authority, err := newVolumeAuthoritySnapshot(approved, found)
	if err != nil {
		t.Fatal(err)
	}
	approved.Volumes[0].Serial = "1"
	found[0].Serial64 = "2"
	for _, tc := range []struct{ id, guid, serial string }{
		{"data", volumeDataGUID, "15172277115761558407"},
		{"system", volumeSystemGUID, "14888954410052949637"},
	} {
		got, err := authority.resolve(tc.id)
		if err != nil {
			t.Fatal(err)
		}
		if got.EnrollmentID != tc.id || got.VolumeGUID != tc.guid || got.Serial64 != tc.serial {
			t.Fatalf("changed authority for %q: %+v", tc.id, got)
		}
	}
}

func TestApprovedVolumeAuthoritySeparatesOfflineAndHealthyVolumes(t *testing.T) {
	approved := approvedVolumeFixture(t)
	found := volumeDiscoveryFixture()
	found[0].Status = volumediscovery.Unavailable
	found[0].Serial64 = ""
	found[0].Detail = "access denied"
	authority, err := newVolumeAuthoritySnapshot(approved, found)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.resolve("data"); err == nil || !strings.Contains(err.Error(), string(volumediscovery.NotEligible)) {
		t.Fatalf("offline requested volume was authorized: %v", err)
	}
	if _, err := authority.resolve("system"); err != nil {
		t.Fatalf("unrelated volume blocked: %v", err)
	}
}

func TestVolumeAuthorityRefusesChangedOrMissingAndUnknownIDs(t *testing.T) {
	tests := []struct {
		name string
		edit func([]volumediscovery.Snapshot) []volumediscovery.Snapshot
	}{
		{"formatted", func(items []volumediscovery.Snapshot) []volumediscovery.Snapshot {
			items[0].Serial64 = "15172277115761558408"
			return items
		}},
		{"missing", func(items []volumediscovery.Snapshot) []volumediscovery.Snapshot {
			return items[1:]
		}},
		{"unsupported", func(items []volumediscovery.Snapshot) []volumediscovery.Snapshot {
			items[0].FileSystem = "ReFS"
			items[0].Status = volumediscovery.Unsupported
			items[0].Detail = "not NTFS"
			return items
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			authority, err := newVolumeAuthoritySnapshot(approvedVolumeFixture(t), tc.edit(volumeDiscoveryFixture()))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := authority.resolve("data"); err == nil {
				t.Fatal("unsafe source accepted")
			}
			if _, err := authority.resolve("system"); err != nil {
				t.Fatalf("fault blocked unrelated volume: %v", err)
			}
		})
	}
	authority, err := newVolumeAuthoritySnapshot(approvedVolumeFixture(t), volumeDiscoveryFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "C:\\", "../data", "DATA", "system ", "unknown", strings.Repeat("a", 65)} {
		if _, err := authority.resolve(id); err == nil {
			t.Fatalf("unapproved enrollment %q was authorized", id)
		}
	}
}

func TestVolumeAuthorityRejectsMalformedSourceAndConfiguration(t *testing.T) {
	approved := approvedVolumeFixture(t)
	if _, err := newVolumeAuthoritySnapshot(approved, nil); err == nil {
		t.Fatal("empty native discovery accepted")
	}
	approved.Volumes[0].ID = "../traversal"
	if _, err := newVolumeAuthoritySnapshot(approved, volumeDiscoveryFixture()); err == nil {
		t.Fatal("invalid on-disk scope accepted")
	}
	bad := volumeDiscoveryFixture()
	bad = append(bad, bad[0])
	if _, err := newVolumeAuthoritySnapshot(approvedVolumeFixture(t), bad); err == nil {
		t.Fatal("duplicate native volume accepted")
	}
}
