// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// A bounded, deterministic security ingest profile controller. It accepts only
// evidence from completely committed generations; it has no goroutines, clock,
// SQL access, mutable process globals or resource-probing side effects.
package recordingest

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"
)

const (
	securityAdaptiveRequiredWins      = 2
	securityAdaptiveCooldown          = 3
	securityAdaptiveMinGain           = 1.10
	securityAdaptiveWorkloadTolerance = 0.15
	securityAdaptiveMaxCPU            = 0.85
	securityAdaptiveMaxRSSFraction    = 0.75
)

type securityAdaptivePressure struct {
	// Complete means every field was sampled for the whole generation's SQL
	// interval. If absent, capacity is unknown and the controller falls back.
	Complete         bool
	CPUFraction      float64 // 0..1, relative to the ingest jail's effective CPU allowance
	PeakRSSBytes     uint64
	MemoryLimitBytes uint64 // effective jail/process ceiling, not host installed RAM
	StorageP95       time.Duration
	StorageLimit     time.Duration // configured local operating ceiling
}

type securityAdaptiveSample struct {
	SourceID               string
	GenerationID           string
	Profile                string
	Committed              bool
	SourceRecordsCommitted int64
	SecurityEvents         int64
	SecurityFields         int64
	SecuritySourceBytes    int64
	// The longest uninterrupted security-record sequence within ONE signed
	// source batch. No cross-batch pooling is ever inferred or authorized.
	MaxContiguousSecurity int
	// The measured duration of the COMPLETE committed relational generation
	// transaction, not field COPY time, raw collector events or staging time.
	IngestDuration time.Duration
	Pressure       securityAdaptivePressure
}

type securityAdaptiveDecision struct {
	Previous string
	Next     string
	Reason   string
	Trials   int
	Wins     int
}

type securityAdaptivePhase uint8

const (
	securityAdaptiveBaseline securityAdaptivePhase = iota
	securityAdaptiveCandidate
	securityAdaptivePairedBaseline
)

// One instance is owned by ONE source's serial generation-ingest loop.
// Concurrent sources must use separate instances; caller serializes Observe.
// All decisions apply to the NEXT generation, never the current transaction.
type securityAdaptiveController struct {
	ceiling         int
	current         int
	phase           securityAdaptivePhase
	cooldown        int
	baselineSamples int
	trials          int
	wins            int
	candidate       securityAdaptiveSample
	baseline        securityAdaptiveSample
	lastGeneration  string
	sourceID        string
}

func newSecurityAdaptiveController(maxProfile string) (*securityAdaptiveController, error) {
	ceiling, err := securityAdaptiveProfileNumber(maxProfile)
	if err != nil {
		return nil, err
	}
	return &securityAdaptiveController{ceiling: ceiling, current: 1}, nil
}

func securityAdaptiveProfileNumber(name string) (int, error) {
	if len(name) != 2 || name[0] != 'P' || name[1] < '1' || name[1] > '5' {
		return 0, fmt.Errorf("FI adaptive security: invalid profile ceiling %q", name)
	}
	return int(name[1] - '0'), nil
}

// profileName is only called on validated, bounded controller integers.
func (c *securityAdaptiveController) profileName() string {
	if c == nil {
		return "P1"
	}
	number := c.current
	if c.phase == securityAdaptiveCandidate {
		number++
	}
	if number < 1 || number > c.ceiling {
		return "P1"
	}
	return fmt.Sprintf("P%d", number)
}

// contextForNextGeneration binds immutable limits to a new ingestion context.
// It must be called before the signed-generation transaction begins.
func (c *securityAdaptiveController) contextForNextGeneration(ctx context.Context) (context.Context, error) {
	if c == nil {
		return withFixedSecurityBulkProfile(ctx, "P1")
	}
	return withFixedSecurityBulkProfile(ctx, c.profileName())
}

// compareWorkload rejects apples-to-oranges score comparisons. Counts and
// average byte/field expansion must all be within 15% of the reference.
func securityAdaptiveComparable(a, b securityAdaptiveSample) bool {
	comparable := func(x, y float64) bool {
		if x <= 0 || y <= 0 {
			return false
		}
		return math.Abs(x-y)/math.Max(x, y) <= securityAdaptiveWorkloadTolerance
	}
	return comparable(float64(a.SecurityEvents), float64(b.SecurityEvents)) &&
		comparable(float64(a.SecurityFields), float64(b.SecurityFields)) &&
		comparable(float64(a.SecuritySourceBytes), float64(b.SecuritySourceBytes)) &&
		comparable(float64(a.MaxContiguousSecurity), float64(b.MaxContiguousSecurity))
}

func (p securityAdaptivePressure) healthy() bool {
	if !p.Complete || p.MemoryLimitBytes == 0 || p.StorageLimit <= 0 ||
		math.IsNaN(p.CPUFraction) || math.IsInf(p.CPUFraction, 0) ||
		p.CPUFraction < 0 || p.CPUFraction > securityAdaptiveMaxCPU ||
		p.PeakRSSBytes == 0 || p.StorageP95 < 0 || p.StorageP95 > p.StorageLimit {
		return false
	}
	// Avoid overflow and preserve strict headroom.
	return float64(p.PeakRSSBytes)/float64(p.MemoryLimitBytes) <= securityAdaptiveMaxRSSFraction
}

func (s securityAdaptiveSample) valid() bool {
	if s.SourceID == "" || s.GenerationID == "" {
		return false
	}
	if !s.Committed {
		return true
	}
	if s.SourceRecordsCommitted <= 0 || s.SecurityEvents <= 0 ||
		s.SecurityFields < 0 || s.SecuritySourceBytes <= 0 || s.IngestDuration <= 0 ||
		s.MaxContiguousSecurity <= 0 || int64(s.MaxContiguousSecurity) > s.SecurityEvents {
		return false
	}
	return true
}

func (c *securityAdaptiveController) reset(reason, previous string) securityAdaptiveDecision {
	c.current = 1
	c.phase = securityAdaptiveBaseline
	c.cooldown = securityAdaptiveCooldown
	c.baselineSamples = 0
	c.trials = 0
	c.wins = 0
	c.candidate = securityAdaptiveSample{}
	c.baseline = securityAdaptiveSample{}
	return securityAdaptiveDecision{Previous: previous, Next: "P1", Reason: reason}
}

// observe evaluates an authoritative ACCEPTED result only after COMMIT was
// confirmed. It cannot change any limits inside the completed generation.
// Unknown resources or a rejection cause a conservative P1 reset. A pair is
// candidate-then-baseline on comparable workloads; TWO winning pairs with at
// least 10% committed generation rate improvement are required to promote.
func (c *securityAdaptiveController) observe(s securityAdaptiveSample) (securityAdaptiveDecision, error) {
	if c == nil {
		return securityAdaptiveDecision{}, errors.New("FI adaptive security: nil controller")
	}
	previous := c.profileName()
	if !s.valid() {
		return c.reset("invalid_sample", previous), errors.New("FI adaptive security: invalid sample")
	}
	if s.GenerationID == c.lastGeneration {
		return securityAdaptiveDecision{}, errors.New("FI adaptive security: duplicate generation sample")
	}
	if c.sourceID != "" && s.SourceID != c.sourceID {
		return securityAdaptiveDecision{}, errors.New("FI adaptive security: source identity changed")
	}
	if s.Profile != previous {
		return securityAdaptiveDecision{}, fmt.Errorf("FI adaptive security: measured profile %q expected %q", s.Profile, previous)
	}
	if c.sourceID == "" {
		c.sourceID = s.SourceID
	}
	c.lastGeneration = s.GenerationID
	if !s.Committed {
		return c.reset("rejected_generation", previous), nil
	}
	if !s.Pressure.healthy() {
		return c.reset("missing_or_high_resource_pressure", previous), nil
	}
	// Generations mixing different record kinds are not comparable to the
	// Security-only test population. Never misrepresent security event rate
	// as complete source-record throughput for a mixed generation.
	if s.SourceRecordsCommitted != s.SecurityEvents {
		return c.reset("mixed_generation_not_comparable", previous), nil
	}
	if c.ceiling == 1 {
		return securityAdaptiveDecision{Previous: previous, Next: previous, Reason: "fixed_P1_ceiling"}, nil
	}
	if c.cooldown > 0 {
		c.cooldown--
		return securityAdaptiveDecision{Previous: previous, Next: c.profileName(), Reason: "cooldown"}, nil
	}
	switch c.phase {
	case securityAdaptiveBaseline:
		if c.current >= c.ceiling {
			return securityAdaptiveDecision{Previous: previous, Next: previous, Reason: "profile_ceiling"}, nil
		}
		next, _ := securityBulkFixedProfile(fmt.Sprintf("P%d", c.current+1))
		if s.MaxContiguousSecurity <= next.MaxRecords/2 {
			c.baselineSamples = 0
			return securityAdaptiveDecision{Previous: previous, Next: previous, Reason: "source_batch_too_small"}, nil
		}
		if c.baselineSamples == 0 || !securityAdaptiveComparable(s, c.baseline) {
			c.baseline = s
			c.baselineSamples = 1
			return securityAdaptiveDecision{Previous: previous, Next: previous, Reason: "collect_comparable_baseline"}, nil
		}
		c.baselineSamples++
		if c.baselineSamples < 2 {
			return securityAdaptiveDecision{Previous: previous, Next: previous, Reason: "collect_comparable_baseline"}, nil
		}
		c.phase = securityAdaptiveCandidate
		c.baselineSamples = 0
		c.trials = 0
		c.wins = 0
		return securityAdaptiveDecision{Previous: previous, Next: c.profileName(), Reason: "trial_candidate"}, nil
	case securityAdaptiveCandidate:
		c.candidate = s
		c.phase = securityAdaptivePairedBaseline
		return securityAdaptiveDecision{Previous: previous, Next: c.profileName(), Reason: "paired_baseline_required", Trials: c.trials, Wins: c.wins}, nil
	case securityAdaptivePairedBaseline:
		c.trials++
		// A different workload does not count as a loss; it invalidates the
		// comparison and forces a fresh baseline with conservative limits.
		if !securityAdaptiveComparable(s, c.candidate) {
			c.phase = securityAdaptiveBaseline
			c.baselineSamples = 0
			c.trials = 0
			c.wins = 0
			c.cooldown = securityAdaptiveCooldown
			return securityAdaptiveDecision{Previous: previous, Next: c.profileName(), Reason: "incomparable_workloads"}, nil
		}
		candidateRate := float64(c.candidate.SecurityEvents) / c.candidate.IngestDuration.Seconds()
		baselineRate := float64(s.SecurityEvents) / s.IngestDuration.Seconds()
		if candidateRate >= securityAdaptiveMinGain*baselineRate {
			c.wins++
		}
		if c.trials < securityAdaptiveRequiredWins {
			c.phase = securityAdaptiveCandidate
			return securityAdaptiveDecision{Previous: previous, Next: c.profileName(), Reason: "second_pair_required", Trials: c.trials, Wins: c.wins}, nil
		}
		decision := securityAdaptiveDecision{Previous: previous, Trials: c.trials, Wins: c.wins}
		if c.wins == securityAdaptiveRequiredWins {
			c.current++
			decision.Reason = "promoted_two_comparable_pairs"
		} else {
			c.cooldown = securityAdaptiveCooldown
			decision.Reason = "candidate_not_proven"
		}
		c.phase = securityAdaptiveBaseline
		c.baselineSamples = 0
		c.trials = 0
		c.wins = 0
		decision.Next = c.profileName()
		return decision, nil
	default:
		return c.reset("invalid_state", previous), nil
	}
}
