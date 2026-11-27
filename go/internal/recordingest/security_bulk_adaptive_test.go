// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"
)

func securityAdaptiveTestSample(c *securityAdaptiveController, id string, dur time.Duration) securityAdaptiveSample {
	return securityAdaptiveSample{
		SourceID: "iss-security-test.iss.local", GenerationID: id,
		Profile: c.profileName(), Committed: true,
		SourceRecordsCommitted: 16384, SecurityEvents: 16384, SecurityFields: 16384 * 15,
		SecuritySourceBytes: 16384 * 4200, MaxContiguousSecurity: 16384,
		IngestDuration: dur,
		Pressure: securityAdaptivePressure{
			Complete: true, CPUFraction: 0.45, PeakRSSBytes: 1024 << 20,
			MemoryLimitBytes: 8192 << 20, StorageP95: 3 * time.Millisecond,
			StorageLimit: 20 * time.Millisecond,
		},
	}
}

func mustSecurityAdaptive(t *testing.T, max string) *securityAdaptiveController {
	t.Helper()
	c, e := newSecurityAdaptiveController(max)
	if e != nil {
		t.Fatal(e)
	}
	return c
}

func securityAdaptiveObserve(t *testing.T, c *securityAdaptiveController, id string, dur time.Duration) securityAdaptiveDecision {
	t.Helper()
	d, e := c.observe(securityAdaptiveTestSample(c, id, dur))
	if e != nil {
		t.Fatal(e)
	}
	return d
}

func TestFISecurityAdaptiveTwoPairedWinsRequired(t *testing.T) {
	c := mustSecurityAdaptive(t, "P5")
	if c.profileName() != "P1" {
		t.Fatal("unsafe starting profile")
	}
	if x := securityAdaptiveObserve(t, c, "baseline-1", 10*time.Second); x.Next != "P1" {
		t.Fatalf("first baseline promoted: %+v", x)
	}
	if x := securityAdaptiveObserve(t, c, "baseline-2", 10*time.Second); x.Next != "P2" {
		t.Fatalf("P2 trial not scheduled: %+v", x)
	}
	if x := securityAdaptiveObserve(t, c, "candidate-1", 8*time.Second); x.Next != "P1" {
		t.Fatalf("paired baseline not required: %+v", x)
	}
	if x := securityAdaptiveObserve(t, c, "paired-1", 10*time.Second); x.Next != "P2" || x.Wins != 1 {
		t.Fatalf("first pair accepted too soon: %+v", x)
	}
	if x := securityAdaptiveObserve(t, c, "candidate-2", 8*time.Second); x.Next != "P1" {
		t.Fatalf("second pair missing baseline: %+v", x)
	}
	if x := securityAdaptiveObserve(t, c, "paired-2", 10*time.Second); x.Next != "P2" || x.Wins != 2 || x.Reason != "promoted_two_comparable_pairs" {
		t.Fatalf("promotion incorrect: %+v", x)
	}
	ctx, err := c.contextForNextGeneration(context.Background())
	if err != nil || securityBulkLimitsFromContext(ctx).MaxRecords != 2048 {
		t.Fatalf("profile not wired to flush limits: %+v %v", securityBulkLimitsFromContext(ctx), err)
	}
	if securityBulkLimitsFromContext(context.Background()).Name != "P1" {
		t.Fatal("default overridden globally")
	}
}

func TestFISecurityAdaptiveRejectionAndPressureFallBack(t *testing.T) {
	c := mustSecurityAdaptive(t, "P5")
	securityAdaptiveObserve(t, c, "b1", 10*time.Second)
	securityAdaptiveObserve(t, c, "b2", 10*time.Second)
	bad := securityAdaptiveTestSample(c, "reject", 0)
	bad.Committed = false
	bad.SecurityEvents = 0
	bad.SecurityFields = 0
	bad.IngestDuration = 0
	d, e := c.observe(bad)
	if e != nil || d.Next != "P1" || d.Reason != "rejected_generation" {
		t.Fatalf("rejection response: %+v %v", d, e)
	}
	for i := 0; i < 3; i++ {
		x := securityAdaptiveObserve(t, c, string(rune('a'+i)), 10*time.Second)
		if x.Reason != "cooldown" {
			t.Fatalf("cooldown %d: %+v", i, x)
		}
	}
	securityAdaptiveObserve(t, c, "b3", 10*time.Second)
	securityAdaptiveObserve(t, c, "b4", 10*time.Second)
	pressure := securityAdaptiveTestSample(c, "pressure", 8*time.Second)
	pressure.Pressure.StorageP95 = 21 * time.Millisecond
	d, e = c.observe(pressure)
	if e != nil || d.Next != "P1" || d.Reason != "missing_or_high_resource_pressure" {
		t.Fatalf("pressure response: %+v %v", d, e)
	}
}

func TestFISecurityAdaptiveNoUnprovenPromotion(t *testing.T) {
	c := mustSecurityAdaptive(t, "P4")
	securityAdaptiveObserve(t, c, "b1", 10*time.Second)
	securityAdaptiveObserve(t, c, "b2", 10*time.Second)
	securityAdaptiveObserve(t, c, "c1", 12*time.Second)
	d := securityAdaptiveObserve(t, c, "p1", 10*time.Second)
	if d.Wins != 0 {
		t.Fatal("slower candidate credited")
	}
	securityAdaptiveObserve(t, c, "c2", 10*time.Second)
	d = securityAdaptiveObserve(t, c, "p2", 10*time.Second)
	if d.Next != "P1" || d.Reason != "candidate_not_proven" {
		t.Fatalf("unproven promoted: %+v", d)
	}
}

func TestFISecurityAdaptiveWorkloadAndSmallSourceBatch(t *testing.T) {
	c := mustSecurityAdaptive(t, "P5")
	first := securityAdaptiveTestSample(c, "small", 5*time.Second)
	first.SecurityEvents = 1024
	first.SourceRecordsCommitted = 1024
	first.SecurityFields = 1024 * 15
	first.SecuritySourceBytes = 1024 * 4200
	first.MaxContiguousSecurity = 1024
	d, e := c.observe(first)
	if e != nil || d.Next != "P1" || d.Reason != "source_batch_too_small" {
		t.Fatalf("small source batch: %+v %v", d, e)
	}
	securityAdaptiveObserve(t, c, "b1", 10*time.Second)
	securityAdaptiveObserve(t, c, "b2", 10*time.Second)
	securityAdaptiveObserve(t, c, "c1", 8*time.Second)
	changed := securityAdaptiveTestSample(c, "different", 10*time.Second)
	changed.SecurityFields *= 3
	d, e = c.observe(changed)
	if e != nil || d.Next != "P1" || d.Reason != "incomparable_workloads" {
		t.Fatalf("bad comparison: %+v %v", d, e)
	}
}

func TestFISecurityAdaptiveInvalidSignalsAndIdentity(t *testing.T) {
	for _, max := range []string{"", "P0", "P6", "p5", "P55"} {
		if _, err := newSecurityAdaptiveController(max); err == nil {
			t.Fatalf("accepted %q", max)
		}
	}
	c := mustSecurityAdaptive(t, "P1")
	good := securityAdaptiveTestSample(c, "id1", 5*time.Second)
	if _, e := c.observe(good); e != nil {
		t.Fatal(e)
	}
	if _, e := c.observe(good); e == nil {
		t.Fatal("duplicate evidence accepted")
	}
	changed := securityAdaptiveTestSample(c, "id2", 5*time.Second)
	changed.SourceID = "different-source"
	if _, e := c.observe(changed); e == nil {
		t.Fatal("source identity changed")
	}
	changed = securityAdaptiveTestSample(c, "id3", 5*time.Second)
	changed.Profile = "P5"
	if _, e := c.observe(changed); e == nil {
		t.Fatal("wrong profile evidence accepted")
	}
	changed = securityAdaptiveTestSample(c, "id4", 5*time.Second)
	changed.Pressure.CPUFraction = math.NaN()
	d, e := c.observe(changed)
	if e != nil || d.Next != "P1" {
		t.Fatalf("NaN capacity fail open: %+v %v", d, e)
	}
	if name := c.profileName(); name != "P1" {
		t.Fatal("ceiling bypass")
	}
}

func TestFISecurityAdaptiveMissingCapacityNeverPromotes(t *testing.T) {
	c := mustSecurityAdaptive(t, "P5")
	for i := 0; i < 5; i++ {
		s := securityAdaptiveTestSample(c, string(rune('a'+i)), 2*time.Second)
		s.Pressure.Complete = false
		d, e := c.observe(s)
		if e != nil || d.Next != "P1" {
			t.Fatalf("unknown capacity promoted: %+v %v", d, e)
		}
	}
}

func TestFISecurityAdaptiveImmutableGenerationContext(t *testing.T) {
	c := mustSecurityAdaptive(t, "P5")
	ctx, err := c.contextForNextGeneration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	securityAdaptiveObserve(t, c, "b1", 10*time.Second)
	securityAdaptiveObserve(t, c, "b2", 10*time.Second)
	if securityBulkLimitsFromContext(ctx).Name != "P1" {
		t.Fatal("existing transaction profile changed")
	}
	next, err := c.contextForNextGeneration(context.Background())
	if err != nil || securityBulkLimitsFromContext(next).Name != "P2" {
		t.Fatalf("new profile not selected: %v", err)
	}
	if securityBulkLimitsFromContext(context.Background()).Name != "P1" {
		t.Fatal("global default changed")
	}
}

// Repeated two-pair wins must never jump profiles or cross the configured
// ceiling, even when the samples imply abundant bandwidth and memory.
func TestFISecurityAdaptiveProgressesOneProfileAtATime(t *testing.T) {
	c := mustSecurityAdaptive(t, "P5")
	id := 0
	next := func(d time.Duration) securityAdaptiveDecision {
		id++
		return securityAdaptiveObserve(t, c, fmt.Sprintf("progress-%d", id), d)
	}
	for target := 2; target <= 5; target++ {
		next(10 * time.Second)
		d := next(10 * time.Second)
		if d.Next != fmt.Sprintf("P%d", target) {
			t.Fatalf("missing target %d trial: %+v", target, d)
		}
		next(8 * time.Second)
		next(10 * time.Second)
		next(8 * time.Second)
		d = next(10 * time.Second)
		if d.Next != fmt.Sprintf("P%d", target) || d.Reason != "promoted_two_comparable_pairs" {
			t.Fatalf("promotion %d: %+v", target, d)
		}
	}
	for i := 0; i < 5; i++ {
		if d := next(10 * time.Second); d.Next != "P5" {
			t.Fatalf("ceiling ignored: %+v", d)
		}
	}
}

func TestFISecurityAdaptiveDoesNotMutateContextOnSampleError(t *testing.T) {
	c := mustSecurityAdaptive(t, "P4")
	securityAdaptiveObserve(t, c, "b1", 10*time.Second)
	securityAdaptiveObserve(t, c, "b2", 10*time.Second)
	already, err := c.contextForNextGeneration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	invalid := securityAdaptiveTestSample(c, "bad", 10*time.Second)
	invalid.SecurityEvents = -1
	if _, err = c.observe(invalid); err == nil {
		t.Fatal("invalid sample accepted")
	}
	if c.profileName() != "P1" {
		t.Fatal("invalid sample failed open")
	}
	if securityBulkLimitsFromContext(already).Name != "P2" {
		t.Fatal("context changed after sample failure")
	}
}

func TestFISecurityAdaptiveMixedGenerationCannotPromote(t *testing.T) {
	c := mustSecurityAdaptive(t, "P5")
	securityAdaptiveObserve(t, c, "b1", 10*time.Second)
	securityAdaptiveObserve(t, c, "b2", 10*time.Second)
	mixed := securityAdaptiveTestSample(c, "mixed", 10*time.Second)
	mixed.SourceRecordsCommitted = mixed.SecurityEvents + 1
	d, err := c.observe(mixed)
	if err != nil || d.Next != "P1" || d.Reason != "mixed_generation_not_comparable" {
		t.Fatalf("mixed generated promotion: %+v %v", d, err)
	}
}
