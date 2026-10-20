// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"time"
)

type ntfsNestedStageContextKey struct{}
type ntfsStageTimingContextKey struct{}

type ntfsStageTimingCounters struct {
	Observations int64
	Total        time.Duration
	Identity     time.Duration
	File         time.Duration
	Metadata     time.Duration
	Hashes       time.Duration
	Prefix       time.Duration
	Reparse      time.Duration
	Streams      time.Duration
	Security     time.Duration
	SACL         time.Duration
	Warnings     time.Duration
}

type ntfsStageRecorder struct {
	counters     *ntfsStageTimingCounters
	totalStarted time.Time
	phaseStarted time.Time
}

func beginNTFSStage(ctx context.Context) ntfsStageRecorder {
	if ctx.Value(ntfsNestedStageContextKey{}) != true {
		return ntfsStageRecorder{}
	}

	counters, ok := ctx.Value(
		ntfsStageTimingContextKey{},
	).(*ntfsStageTimingCounters)

	if !ok || counters == nil {
		return ntfsStageRecorder{}
	}

	now := time.Now()

	return ntfsStageRecorder{
		counters:     counters,
		totalStarted: now,
		phaseStarted: now,
	}
}

func (r *ntfsStageRecorder) mark(stage string) {
	if r.counters == nil {
		return
	}

	elapsed := time.Since(r.phaseStarted)

	switch stage {
	case "identity":
		r.counters.Identity += elapsed
	case "file":
		r.counters.File += elapsed
	case "metadata":
		r.counters.Metadata += elapsed
	case "hashes":
		r.counters.Hashes += elapsed
	case "prefix":
		r.counters.Prefix += elapsed
	case "reparse":
		r.counters.Reparse += elapsed
	case "streams":
		r.counters.Streams += elapsed
	case "security":
		r.counters.Security += elapsed
	case "sacl":
		r.counters.SACL += elapsed
	case "warnings":
		r.counters.Warnings += elapsed
	}

	r.phaseStarted = time.Now()
}

func (r *ntfsStageRecorder) finish() {
	if r.counters == nil {
		return
	}

	r.counters.Total += time.Since(r.totalStarted)
	r.counters.Observations++
}

func (c *ntfsStageTimingCounters) accounted() time.Duration {
	return c.Identity +
		c.File +
		c.Metadata +
		c.Hashes +
		c.Prefix +
		c.Reparse +
		c.Streams +
		c.Security +
		c.SACL +
		c.Warnings
}
