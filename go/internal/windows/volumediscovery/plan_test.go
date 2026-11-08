// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package volumediscovery

import (
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
)

const (
	dataGUID = `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`
	systemGUID = `\\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\`
	otherGUID = `\\?\Volume{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}\`
)

func requestedVolumes(t *testing.T) config.VolumeConfig {
	t.Helper()
	raw := `version_id: 2.0
volume.data.guid = \\?\Volume{18fed846-4275-4251-b698-f268192100f2}\
volume.data.serial = 15172277115761558407
volume.system.guid = \\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\
volume.system.serial = 14888954410052949637
policy.finance.volume = data
policy.finance.root = \Shares\Finance
policy.finance.depth = security
`
	value, err := config.ParseVolumeV2(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func currentVolumes() []Snapshot {
	return []Snapshot{
		{GUID: dataGUID, FileSystem: "NTFS", Serial64: "15172277115761558407", MountPaths: []string{`D:\`}, Status: Eligible},
		{GUID: systemGUID, FileSystem: "NTFS", Serial64: "14888954410052949637", MountPaths: []string{`C:\`}, Status: Eligible},
	}
}

func TestAssessEnrollmentMatchesExplicitVolumes(t *testing.T) {
	request := requestedVolumes(t)
	discovered := append(currentVolumes(), Snapshot{
		GUID: otherGUID, FileSystem: "NTFS", Serial64: "42", Status: Eligible,
	})
	preflight, err := AssessEnrollment(request, discovered)
	if err != nil {
		t.Fatal(err)
	}
	if !preflight.AllVolumesMatch || !preflight.ObservationOnly ||
		len(preflight.Matches) != 2 || len(preflight.Unenrolled) != 1 ||
		preflight.Unenrolled[0].GUID != otherGUID || preflight.PolicyCount != 1 {
		t.Fatalf("unexpected read-only preflight: %+v", preflight)
	}
	for _, match := range preflight.Matches {
		if match.Status != IdentityMatched {
			t.Fatalf("explicitly enrolled volume did not match: %+v", match)
		}
	}
}

func TestAssessEnrollmentRejectsDiscontinuityWithoutAbortingOtherVolumes(t *testing.T) {
	tests := []struct {
		name   string
		change func([]Snapshot) []Snapshot
		want   MatchStatus
	}{
		{"missing volume", func(items []Snapshot) []Snapshot { return items[:1] }, NotDiscovered},
		{"reformatted serial", func(items []Snapshot) []Snapshot {
			items[1].Serial64 = "14888954410052949638"
			return items
		}, IdentityChanged},
		{"inaccessible volume", func(items []Snapshot) []Snapshot {
			items[1].Status = Unavailable
			items[1].Detail = "access denied"
			items[1].Serial64 = ""
			return items
		}, NotEligible},
		{"unsupported filesystem", func(items []Snapshot) []Snapshot {
			items[1].Status = Unsupported
			items[1].Detail = "not NTFS"
			items[1].FileSystem = "ReFS"
			items[1].Serial64 = ""
			return items
		}, NotEligible},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			preflight, err := AssessEnrollment(requestedVolumes(t), tc.change(currentVolumes()))
			if err != nil {
				t.Fatalf("unexpected structural error: %v", err)
			}
			if preflight.AllVolumesMatch || len(preflight.Matches) != 2 ||
				preflight.Matches[0].Status != IdentityMatched ||
				preflight.Matches[1].Status != tc.want {
				t.Fatalf("unsafe scope match: %+v; want second %s", preflight, tc.want)
			}
		})
	}
}

func TestAssessEnrollmentRejectsUntrustedDiscovery(t *testing.T) {
	tests := []struct {
		name string
		add  []Snapshot
	}{
		{"duplicate case-insensitive GUID", []Snapshot{{GUID: strings.ToUpper(dataGUID), Status: Eligible, FileSystem: "NTFS", Serial64: "1"}}},
		{"device path instead of volume GUID", []Snapshot{{GUID: `\\.\PhysicalDrive0`, Status: Eligible, FileSystem: "NTFS", Serial64: "1"}}},
		{"unknown status", []Snapshot{{GUID: otherGUID, Status: "Maybe", FileSystem: "NTFS"}}},
		{"invalid eligible serial", []Snapshot{{GUID: otherGUID, Status: Eligible, FileSystem: "NTFS", Serial64: "0"}}},
		{"inconsistent eligible NTFS", []Snapshot{{GUID: otherGUID, Status: Eligible, FileSystem: "ReFS", Serial64: "42"}}},
		{"missing unavailability reason", []Snapshot{{GUID: otherGUID, Status: Unavailable}}},
		{"unsupported but NTFS", []Snapshot{{GUID: otherGUID, Status: Unsupported, FileSystem: "NTFS", Detail: "unsupported"}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := AssessEnrollment(requestedVolumes(t), append(currentVolumes(), tc.add...))
			if err == nil {
				t.Fatal("unsafe discovery snapshot unexpectedly accepted")
			}
		})
	}
}

func TestAssessEnrollmentRejectsUncheckedConfiguration(t *testing.T) {
	value := requestedVolumes(t)
	value.Volumes[0].ID = "../outside"
	if _, err := AssessEnrollment(value, currentVolumes()); err == nil {
		t.Fatal("configuration not canonical but accepted")
	}
}

func TestCanonicalGUIDRejectsMalformedNativePaths(t *testing.T) {
	for _, value := range []string{"", `C:\`, `\\.\C:`, `\\?\Volume{bad}\`, otherGUID[:len(otherGUID)-1]} {
		if _, err := canonicalGUID(value); err == nil {
			t.Fatalf("accepted malformed volume locator %q", value)
		}
	}
	value, err := canonicalGUID(strings.ToUpper(dataGUID))
	if err != nil || value != dataGUID {
		t.Fatalf("case-normalization failed: got %q, %v", value, err)
	}
}
