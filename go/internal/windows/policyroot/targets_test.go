// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package policyroot

import (
	"errors"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
)

const targetsFixture = `version_id: 2.0
volume.data.guid = \\?\Volume{18fed846-4275-4251-b698-f268192100f2}\
volume.data.serial = 15172277115761558407
volume.system.guid = \\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\
volume.system.serial = 14888954410052949637
policy.software.volume = system
policy.software.root = \Program Files\SW
policy.software.depth = content
policy.programs.volume = system
policy.programs.root = \Program Files
policy.programs.depth = metadata
policy.volume-root.volume = data
policy.volume-root.root = \
policy.volume-root.depth = metadata
`

func testTargets(t *testing.T) config.VolumeConfig {
	t.Helper()
	value, err := config.ParseVolumeV2(strings.NewReader(targetsFixture))
	if err != nil { t.Fatal(err) }
	return value
}

func TestPolicyTargetsAreBoundedAndVolumeSpecific(t *testing.T) {
	scope := testTargets(t)
	selected, roots, err := targetsForVolume(scope, "system")
	if err != nil { t.Fatal(err) }
	if selected.ID != "system" || len(roots) != 2 ||
		roots[0].policyID != "programs" || roots[1].policyID != "software" {
		t.Fatalf("wrong selected native roots: %+v %+v", selected, roots)
	}
	first, err := rootWalkPaths(roots[1])
	if err != nil { t.Fatal(err) }
	want := []string{
		`\\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\`,
		`\\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\Program Files`,
		`\\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\Program Files\SW`,
	}
	if len(first) != len(want) { t.Fatalf("wrong walk: %v", first) }
	for i := range want {
		if first[i] != want[i] { t.Fatalf("walk prefix %d: got %q want %q", i, first[i], want[i]) }
	}
	_, dataRoots, err := targetsForVolume(scope, "data")
	if err != nil || len(dataRoots) != 1 { t.Fatalf("data volume isolation: %v %v", dataRoots, err) }
	rootOnly, err := rootWalkPaths(dataRoots[0])
	if err != nil || len(rootOnly) != 1 { t.Fatalf("volume root not supported: %v %v", rootOnly, err) }
}

func TestPolicyTargetRejectsUnenrolledAndMutatedScope(t *testing.T) {
	scope := testTargets(t)
	if _, _, err := targetsForVolume(scope, "other"); !errors.Is(err, ErrInvalidRootTarget) {
		t.Fatalf("unenrolled volume allowed: %v", err)
	}
	scope.Policies[0].RelativeRoot = `\Program Files\..\Elsewhere`
	if _, _, err := targetsForVolume(scope, "system"); !errors.Is(err, ErrInvalidRootTarget) {
		t.Fatalf("mutated scope accepted: %v", err)
	}
}

func TestPolicyTargetNativeWalkBounds(t *testing.T) {
	base := target{
		guid: `\\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\`,
		relativeRoot: `\Data`,
	}
	cases := []struct { name, root string }{
		{"traversal", `\Data\..\Admin`},
		{"reparse-style UNC", `\\server\share`},
		{"drive alias", `C:\Windows`},
		{"separator gap", `\A\\B`},
		{"alternate stream", `\Data:payload`},
		{"too long", `\` + strings.Repeat("A", maxRootWalkPathBytes)},
		{"too many components", `\` + strings.Repeat(`a\`, maxRootWalkComponents) + "end"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			current := base
			current.relativeRoot = tc.root
			if _, err := rootWalkPaths(current); !errors.Is(err, ErrInvalidRootTarget) {
				t.Fatalf("bad native path accepted: %q: %v", tc.root, err)
			}
		})
	}
}
