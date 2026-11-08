// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package volumereview

import (
	"errors"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/volumediscovery"
)

const (
	dataGUID = `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`
	systemGUID = `\\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\`
	extraGUID = `\\?\Volume{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}\`
)

func requested(t *testing.T) config.VolumeConfig {
	t.Helper()
	raw := `version_id: 2.0
volume.data.guid = \\?\Volume{18fed846-4275-4251-b698-f268192100f2}\
volume.data.serial = 15172277115761558407
volume.system.guid = \\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\
volume.system.serial = 14888954410052949637
policy.finance.volume = data
policy.finance.root = \Shares\Finance
policy.finance.depth = security
policy.software.volume = system
policy.software.root = \Program Files\SW
policy.software.depth = metadata
`
	v, err := config.ParseVolumeV2(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func native() []volumediscovery.Snapshot {
	return []volumediscovery.Snapshot{
		{GUID: dataGUID, Serial64: "15172277115761558407", FileSystem: "NTFS", Status: volumediscovery.Eligible, MountPaths: []string{`D:\`}},
		{GUID: systemGUID, Serial64: "14888954410052949637", FileSystem: "NTFS", Status: volumediscovery.Eligible, MountPaths: []string{`C:\`}},
	}
}

func TestInitialEnrollmentReviewNeverAuthorizesCollection(t *testing.T) {
	v, err := Build(nil, requested(t), native())
	if err != nil {
		t.Fatal(err)
	}
	if v.Version != ReviewVersion || v.BlocksMutation || !v.AllRequestedVolumesMatch ||
		!v.RequiresExplicitApproval || len(v.Changes) != 4 || len(v.NativeIdentities) != 2 ||
		len(v.RequestedConfigSHA256) != 64 || len(v.ReviewFingerprintSHA256) != 64 ||
		v.CurrentConfigSHA256 != "" {
		t.Fatalf("unexpected new scope review: %+v", v)
	}
	seen := map[ChangeKind]int{}
	for _, change := range v.Changes {
		seen[change.Kind]++
	}
	if seen[VolumeAdded] != 2 || seen[PolicyAdded] != 2 {
		t.Fatalf("initial scope did not require all enrollments and policies: %+v", v.Changes)
	}
	if err := Revalidate(v, nil, requested(t), native()); err != nil {
		t.Fatalf("unchanged review unexpectedly considered stale: %v", err)
	}
}

func TestReviewStableAcrossNativeOrderAndMountAliases(t *testing.T) {
	original, err := Build(nil, requested(t), native())
	if err != nil {
		t.Fatal(err)
	}
	changed := native()
	changed[0], changed[1] = changed[1], changed[0]
	changed[0].MountPaths = []string{`C:\Mounted\Another\`}
	changed[1].MountPaths = nil
	v, err := Build(nil, requested(t), changed)
	if err != nil {
		t.Fatal(err)
	}
	if v.ReviewFingerprintSHA256 != original.ReviewFingerprintSHA256 {
		t.Fatal("different native enumeration order or mount-point alias changed volume authorization evidence")
	}
	if err := Revalidate(original, nil, requested(t), changed); err != nil {
		t.Fatalf("drive-letter/mount change alone invalidated native volume identity: %v", err)
	}
	// Previously unknown new disks must not be silently enrolled nor change
	// approval for two explicitly enrolled native identities.
	changed = append(changed, volumediscovery.Snapshot{
		GUID: extraGUID, Serial64: "42", FileSystem: "NTFS", Status: volumediscovery.Eligible,
	})
	if err := Revalidate(original, nil, requested(t), changed); err != nil {
		t.Fatalf("unrequested discovered volume changed explicitly requested scope: %v", err)
	}
}

func TestReviewDetectsChangeBetweenReviewAndFreshDiscovery(t *testing.T) {
	first, err := Build(nil, requested(t), native())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		alter func([]volumediscovery.Snapshot) []volumediscovery.Snapshot
	}{
		{"format changed serial", func(found []volumediscovery.Snapshot) []volumediscovery.Snapshot {
			found[0].Serial64 = "15172277115761558408"
			return found
		}},
		{"volume removed", func(found []volumediscovery.Snapshot) []volumediscovery.Snapshot {
			return found[1:]
		}},
		{"offline", func(found []volumediscovery.Snapshot) []volumediscovery.Snapshot {
			found[0].Status = volumediscovery.Unavailable
			found[0].Serial64 = ""
			found[0].Detail = "access denied"
			return found
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			observed := tc.alter(native())
			review, err := Build(nil, requested(t), observed)
			if err != nil {
				t.Fatal(err)
			}
			if !review.BlocksMutation || review.AllRequestedVolumesMatch {
				t.Fatalf("unsafe native identity was not blocked: %+v", review)
			}
			if err := Revalidate(first, nil, requested(t), observed); !errors.Is(err, ErrStaleReview) {
				t.Fatalf("native drift not recognized: %v", err)
			}
			if err := Revalidate(review, nil, requested(t), observed); !errors.Is(err, ErrStaleReview) {
				t.Fatalf("a blocked review must never be revalidated for use: %v", err)
			}
		})
	}
}

func TestReviewRejectsPolicyAndEnrollmentChangesWithoutNewReview(t *testing.T) {
	initial := requested(t)
	first, err := Build(&initial, initial, native())
	if err != nil {
		t.Fatal(err)
	}
	if first.RequiresExplicitApproval || len(first.Changes) != 0 ||
		first.CurrentConfigSHA256 != first.RequestedConfigSHA256 {
		t.Fatalf("unchanged scope requires an unnecessary new change: %+v", first)
	}
	if err := Revalidate(first, &initial, initial, native()); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		alter func(*config.VolumeConfig)
		kind ChangeKind
	}{
		{"policy depth metadata to content", func(v *config.VolumeConfig) { v.Policies[1].Depth = config.DepthContent }, PolicyChanged},
		{"policy depth security to metadata", func(v *config.VolumeConfig) { v.Policies[0].Depth = config.DepthMetadata }, PolicyChanged},
		{"policy root moved", func(v *config.VolumeConfig) { v.Policies[0].RelativeRoot = `\Shares\Private` }, PolicyChanged},
		{"policy removed", func(v *config.VolumeConfig) { v.Policies = v.Policies[1:] }, PolicyRemoved},
		{"volume identity changed", func(v *config.VolumeConfig) { v.Volumes[0].Serial = "15172277115761558408" }, VolumeIdentityChanged},
		{"volume removed", func(v *config.VolumeConfig) {
			v.Volumes = v.Volumes[:1]
			v.Policies = v.Policies[:1]
		}, VolumeRemoved},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			next := requested(t)
			tc.alter(&next)
			review, err := Build(&initial, next, native())
			if err != nil {
				t.Fatal(err)
			}
			if !review.RequiresExplicitApproval || len(review.Changes) == 0 {
				t.Fatal("policy/scope change did not trigger explicit review")
			}
			found := false
			for _, change := range review.Changes {
				if change.Kind == tc.kind {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing change kind %s: %+v", tc.kind, review.Changes)
			}
			if err := Revalidate(first, &initial, next, native()); !errors.Is(err, ErrStaleReview) {
				t.Fatalf("changed scope accepted against an old fingerprint: %v", err)
			}
		})
	}
}

func TestReviewRejectsMutatedInstalledBaselineAndMalformedSources(t *testing.T) {
	initial := requested(t)
	review, err := Build(&initial, initial, native())
	if err != nil {
		t.Fatal(err)
	}
	modified := requested(t)
	modified.Policies[0].Depth = config.DepthContent
	if err := Revalidate(review, &modified, initial, native()); !errors.Is(err, ErrStaleReview) {
		t.Fatalf("changed installed baseline did not invalidate review: %v", err)
	}
	if _, err := Build(nil, initial, nil); err == nil {
		t.Fatal("empty native discovery erroneously accepted")
	}
	if _, err := Build(nil, config.VolumeConfig{}, native()); err == nil {
		t.Fatal("invalid scope declaration accepted")
	}
	broken := native()
	broken = append(broken, broken[0])
	if _, err := Build(nil, initial, broken); err == nil {
		t.Fatal("duplicate native GUID accepted")
	}
	badPrevious := review
	badPrevious.Version = "legacy-unsafe-review"
	if err := Revalidate(badPrevious, &initial, initial, native()); !errors.Is(err, ErrStaleReview) {
		t.Fatal("wrong review version accepted")
	}
	badPrevious = review
	badPrevious.ReviewFingerprintSHA256 = "untrusted"
	if err := Revalidate(badPrevious, &initial, initial, native()); !errors.Is(err, ErrStaleReview) {
		t.Fatal("malformed fingerprint accepted")
	}
}
