// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package policyassociation

import (
	"errors"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/config"
)

const scopeFixture = `version_id: 2.0
volume.data.guid = \\?\Volume{18fed846-4275-4251-b698-f268192100f2}\
volume.data.serial = 15172277115761558407
volume.system.guid = \\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\
volume.system.serial = 14888954410052949637
policy.programs.volume = system
policy.programs.root = \Program Files
policy.programs.depth = metadata
policy.software.volume = system
policy.software.root = \Program Files\SW
policy.software.depth = content
policy.finance.volume = system
policy.finance.root = \Shares\Finance
policy.finance.depth = security
`

func fixtureID(b byte) FileID {
	var out FileID
	out[15] = b
	return out
}

func fixturePlan(t *testing.T) (config.VolumeConfig, []RootBinding, Plan) {
	t.Helper()
	cfg, err := config.ParseVolumeV2(strings.NewReader(scopeFixture))
	if err != nil {
		t.Fatal(err)
	}
	roots := []RootBinding{
		{PolicyID: "software", VolumeID: "system", RootID: fixtureID(2)},
		{PolicyID: "finance", VolumeID: "system", RootID: fixtureID(3)},
		{PolicyID: "programs", VolumeID: "system", RootID: fixtureID(1)},
	}
	plan, err := NewPlan(cfg, roots)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, roots, plan
}

func systemEvidence() Evidence {
	return Evidence{
		VolumeID: "system",
		VolumeGUID: `\\?\Volume{f21d9dd4-8111-4be8-83e9-a1429a261cdf}\`,
		VolumeSerial: "14888954410052949637",
		ObjectID: fixtureID(9),
		Ancestors: []FileID{fixtureID(2), fixtureID(1), fixtureID(20)},
		Complete: true,
	}
}

func TestOverlappingPoliciesRemainDistinctAndSorted(t *testing.T) {
	_, _, plan := fixturePlan(t)
	result, err := plan.Evaluate(systemEvidence())
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != Matched || len(result.Memberships) != 2 ||
		result.Memberships[0] != (Membership{PolicyID: "programs", Depth: config.DepthMetadata}) ||
		result.Memberships[1] != (Membership{PolicyID: "software", Depth: config.DepthContent}) {
		t.Fatalf("overlapping policy associations lost or conflated: %+v", result)
	}
	// Matching the exact root object does not require a string path prefix.
	e := systemEvidence()
	e.ObjectID, e.Ancestors = fixtureID(3), []FileID{fixtureID(20)}
	result, err = plan.Evaluate(e)
	if err != nil || result.Status != Matched || len(result.Memberships) != 1 ||
		result.Memberships[0].PolicyID != "finance" {
		t.Fatalf("policy root itself was not associated: %+v %v", result, err)
	}
}

func TestKnownOutsideVsUnknownAndUnenrolledPath(t *testing.T) {
	_, _, plan := fixturePlan(t)
	e := systemEvidence()
	e.ObjectID = fixtureID(8)
	e.Ancestors = []FileID{fixtureID(20)}
	if result, err := plan.Evaluate(e); err != nil || result.Status != Outside {
		t.Fatalf("complete known-outside lineage: %+v %v", result, err)
	}
	e = systemEvidence()
	e.Complete = false
	if result, err := plan.Evaluate(e); err != nil || result.Status != Unknown || len(result.Memberships) != 0 {
		t.Fatalf("incomplete lineage manufactured policy membership: %+v %v", result, err)
	}
	e.Complete = true
	e.CrossedReparseBoundary = true
	if result, err := plan.Evaluate(e); err != nil || result.Status != Unknown || len(result.Memberships) != 0 {
		t.Fatalf("reparse boundary was accepted: %+v %v", result, err)
	}
	// Explicitly enrolled volume with no roots permits minimal observation,
	// but must never acquire an implied governed-root membership.
	e = Evidence{
		VolumeID: "data",
		VolumeGUID: `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\`,
		VolumeSerial: "15172277115761558407",
		ObjectID: fixtureID(8),
	}
	if result, err := plan.Evaluate(e); err != nil || result.Status != Outside || len(result.Memberships) != 0 {
		t.Fatalf("zero-root volume was treated as governed: %+v %v", result, err)
	}
}

func TestRejectsUnboundOrReplacedVolumeAndMalformedLineage(t *testing.T) {
	_, _, plan := fixturePlan(t)
	cases := []struct{
		name string
		edit func(*Evidence)
	}{
		{"unenrolled volume", func(e *Evidence){ e.VolumeID = "other" }},
		{"changed full-width serial", func(e *Evidence){ e.VolumeSerial = "14888954410052949636" }},
		{"changed GUID", func(e *Evidence){ e.VolumeGUID = `\\?\Volume{18fed846-4275-4251-b698-f268192100f2}\` }},
		{"zero object identity", func(e *Evidence){ e.ObjectID = FileID{} }},
		{"zero ancestor", func(e *Evidence){ e.Ancestors[0] = FileID{} }},
		{"self cycle", func(e *Evidence){ e.Ancestors[0] = e.ObjectID }},
		{"repeated ancestor", func(e *Evidence){ e.Ancestors[2] = e.Ancestors[0] }},
		{"lineage too deep", func(e *Evidence){ e.Ancestors = make([]FileID, maxLineageAncestors+1) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := systemEvidence()
			tc.edit(&e)
			if _, err := plan.Evaluate(e); !errors.Is(err, ErrInvalidEvidence) {
				t.Fatalf("invalid source evidence accepted: %v", err)
			}
		})
	}
}

func TestRejectsMissingCrossVolumeOrAliasedBindings(t *testing.T) {
	cfg, roots, _ := fixturePlan(t)
	cases := []struct{
		name string
		bindings []RootBinding
	}{
		{"missing", roots[:2]},
		{"repeated policy", []RootBinding{roots[0], roots[0], roots[2]}},
		{"unknown policy", []RootBinding{roots[0], {PolicyID:"unknown",VolumeID:"system",RootID:fixtureID(7)}, roots[2]}},
		{"wrong volume", []RootBinding{roots[0], {PolicyID:"finance",VolumeID:"data",RootID:fixtureID(3)}, roots[2]}},
		{"empty root ID", []RootBinding{roots[0], {PolicyID:"finance",VolumeID:"system"}, roots[2]}},
		{"alias identity", []RootBinding{roots[0], {PolicyID:"finance",VolumeID:"system",RootID:fixtureID(2)}, roots[2]}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewPlan(cfg, tc.bindings); !errors.Is(err, ErrInvalidBindings) {
				t.Fatalf("bad root binding accepted: %v", err)
			}
		})
	}
}

func TestPlanCopiesApprovedScopeAndBindings(t *testing.T) {
	cfg, roots, plan := fixturePlan(t)
	cfg.Volumes[1].Serial = "1"
	cfg.Policies[0].Depth = config.DepthContent
	roots[0].RootID = fixtureID(55)
	result, err := plan.Evaluate(systemEvidence())
	if err != nil || result.Status != Matched || len(result.Memberships) != 2 ||
		result.Memberships[1].Depth != config.DepthContent {
		t.Fatalf("plan was broadened by mutation of input slices: %+v %v", result, err)
	}
}

func TestRejectsMutatedUncanonicalScope(t *testing.T) {
	cfg, roots, _ := fixturePlan(t)
	cfg.Policies[0].RelativeRoot = `\foo\..\bar`
	if _, err := NewPlan(cfg, roots); !errors.Is(err, ErrInvalidBindings) {
		t.Fatalf("mutated uncanonical scope accepted: %v", err)
	}
}
