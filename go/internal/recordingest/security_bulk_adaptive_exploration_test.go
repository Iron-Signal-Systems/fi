// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// These deterministic tests deliberately use only committed signed-generation
// outcome samples. They cannot affect the FreeBSD worker or database.
func explorationFixture(c *securityAdaptiveController, id string, duration time.Duration) securityAdaptiveSample {
	return securityAdaptiveSample{
		SourceID: "iss-fs-22.iss.local", GenerationID: id,
		Profile: c.profileName(), Committed: true,
		SourceRecordsCommitted: 16384, SecurityEvents: 16384,
		SecurityFields: 245760, SecuritySourceBytes: 64 << 20,
		MaxContiguousSecurity: 16384, IngestDuration: duration,
		Pressure: securityAdaptivePressure{
			Complete: true, CPUFraction: 0.45,
			PeakRSSBytes: 256 << 20, MemoryLimitBytes: 4096 << 20,
			StorageP95: 3 * time.Millisecond, StorageLimit: 20 * time.Millisecond,
		},
	}
}

func observeExploration(t *testing.T, c *securityAdaptiveController, label string, dur time.Duration) securityAdaptiveDecision {
	t.Helper()
	got, err := c.observe(explorationFixture(c, label, dur))
	if err != nil {
		t.Fatalf("observation %s: %v", label, err)
	}
	return got
}

// Feed a complete two-pair trial, including the two baseline samples needed
// before the candidate is permitted to run. The caller controls the relative
// candidate duration to prove that comparisons use committed throughput.
func exploreTrial(t *testing.T, c *securityAdaptiveController, target string, base, candidate time.Duration) securityAdaptiveDecision {
	t.Helper()
	for c.cooldown > 0 {
		observeExploration(t, c, fmt.Sprintf("%s-cooldown-%d", target, c.cooldown), base)
	}
	b1 := observeExploration(t, c, target+"-baseline-1", base)
	if b1.Next != c.profileName() {
		t.Fatalf("baseline changed profile: %+v", b1)
	}
	b2 := observeExploration(t, c, target+"-baseline-2", base)
	if b2.Next != target || b2.Reason != "trial_candidate" {
		t.Fatalf("trial %s not scheduled: %+v", target, b2)
	}
	ctx, err := c.contextForNextGeneration(context.Background())
	if err != nil || securityBulkLimitsFromContext(ctx).Name != target {
		t.Fatalf("context not frozen to %s: %v", target, err)
	}
	observeExploration(t, c, target+"-candidate-1", candidate)
	observeExploration(t, c, target+"-paired-baseline-1", base)
	observeExploration(t, c, target+"-candidate-2", candidate)
	return observeExploration(t, c, target+"-paired-baseline-2", base)
}

func TestFIAdaptiveExploreP3DespiteUnprovenP2(t *testing.T) {
	c, err := newSecurityAdaptiveController("P5")
	if err != nil {
		t.Fatal(err)
	}
	if c.profileName() != "P1" {
		t.Fatal("start was not P1")
	}

	// P2's measured 1-2% benefit is insufficient to promote.
	p2 := exploreTrial(t, c, "P2", 10*time.Second, 9850*time.Millisecond)
	if p2.Next != "P1" || p2.Reason != "candidate_not_proven" || p2.Wins != 0 || c.candidateProfile != 3 {
		t.Fatalf("P2 should lose without stopping P3 evaluation: %+v probe=%d", p2, c.candidateProfile)
	}
	// P3 earns two paired wins against P1, without requiring P2 promotion.
	p3 := exploreTrial(t, c, "P3", 10*time.Second, 9200*time.Millisecond)
	if p3.Next != "P3" || p3.Reason != "promoted_two_comparable_pairs" || p3.Wins != 2 || c.current != 3 || c.candidateProfile != 4 {
		t.Fatalf("P3 should be proven independently of P2: %+v current=%d probe=%d", p3, c.current, c.candidateProfile)
	}
	ctx, err := c.contextForNextGeneration(context.Background())
	if err != nil || securityBulkLimitsFromContext(ctx).Name != "P3" {
		t.Fatalf("expected P3 after promotion: %v", err)
	}
}

func TestFIAdaptiveP3RemainsBestWhenP4P5YieldNoGain(t *testing.T) {
	c, err := newSecurityAdaptiveController("P5")
	if err != nil {
		t.Fatal(err)
	}
	exploreTrial(t, c, "P2", 10*time.Second, 9850*time.Millisecond)
	exploreTrial(t, c, "P3", 10*time.Second, 9200*time.Millisecond)
	for _, candidate := range []string{"P4", "P5"} {
		decision := exploreTrial(t, c, candidate, 10*time.Second, 9950*time.Millisecond)
		if decision.Next != "P3" || decision.Reason != "candidate_not_proven" || c.current != 3 {
			t.Fatalf("unproven %s replaced P3: %+v", candidate, decision)
		}
	}
	for i := 0; i < 6; i++ {
		d := observeExploration(t, c, fmt.Sprintf("exhaust-%d", i), 10*time.Second)
		if d.Next != "P3" {
			t.Fatalf("exhausted controller changed profile: %+v", d)
		}
	}
	if c.candidateProfile != 6 {
		t.Fatalf("unexpected probe index %d", c.candidateProfile)
	}
}

func TestFIAdaptiveExplorationFailsClosedOnMissingPressure(t *testing.T) {
	c, err := newSecurityAdaptiveController("P5")
	if err != nil {
		t.Fatal(err)
	}
	exploreTrial(t, c, "P2", 10*time.Second, 9850*time.Millisecond)
	for c.cooldown > 0 {
		observeExploration(t, c, fmt.Sprintf("pressure-cooldown-%d", c.cooldown), 10*time.Second)
	}
	observeExploration(t, c, "p3-baseline-a", 10*time.Second)
	observeExploration(t, c, "p3-baseline-b", 10*time.Second)
	if c.profileName() != "P3" {
		t.Fatalf("P3 trial not scheduled: %s", c.profileName())
	}
	bad := explorationFixture(c, "p3-bad-pressure", 8*time.Second)
	bad.Pressure.Complete = false
	d, e := c.observe(bad)
	if e != nil || d.Next != "P1" || c.candidateProfile != 2 || c.cooldown != securityAdaptiveCooldown {
		t.Fatalf("missing pressure failed to reset: %+v err=%v", d, e)
	}
}

func TestFIAdaptiveExplorationHonorsConfiguredCeiling(t *testing.T) {
	c, err := newSecurityAdaptiveController("P2")
	if err != nil {
		t.Fatal(err)
	}
	d := exploreTrial(t, c, "P2", 10*time.Second, 9850*time.Millisecond)
	if d.Next != "P1" || c.candidateProfile != 3 {
		t.Fatalf("unexpected P2 decision %+v", d)
	}
	for i := 0; i < 8; i++ {
		got := observeExploration(t, c, fmt.Sprintf("ceiling-%d", i), 10*time.Second)
		if got.Next != "P1" {
			t.Fatalf("ceiling breached: %+v", got)
		}
	}
}

func TestFIAdaptiveExplorationDoesNotPromoteMarginalGain(t *testing.T) {
	c, err := newSecurityAdaptiveController("P3")
	if err != nil {
		t.Fatal(err)
	}
	// 4.1% gain is below the 5% minimum.
	d := exploreTrial(t, c, "P2", 10*time.Second, 9600*time.Millisecond)
	if d.Next != "P1" || d.Wins != 0 {
		t.Fatalf("marginal gain promoted: %+v", d)
	}
}

func TestFIAdaptiveExplorationSmallSignedBatchPreservesP3(t *testing.T) {
	c, err := newSecurityAdaptiveController("P5")
	if err != nil {
		t.Fatal(err)
	}
	exploreTrial(t, c, "P2", 10*time.Second, 9850*time.Millisecond)
	exploreTrial(t, c, "P3", 10*time.Second, 9200*time.Millisecond)
	if c.profileName() != "P3" {
		t.Fatal("P3 was not selected")
	}
	limited := explorationFixture(c, "small-signed-batch", 10*time.Second)
	limited.SourceRecordsCommitted = 1024
	limited.SecurityEvents = 1024
	limited.SecurityFields = 1024 * 15
	limited.SecuritySourceBytes = 4 << 20
	limited.MaxContiguousSecurity = 1024
	d, e := c.observe(limited)
	if e != nil || d.Next != "P3" || d.Reason != "source_batch_too_small" || c.candidateProfile != 4 {
		t.Fatalf("small source batch incorrectly moved operating profile: %+v %v", d, e)
	}
}
