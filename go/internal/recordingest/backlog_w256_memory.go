// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// W256 is an isolated, signed-backlog experiment. This controller adjusts
// only the number of whole signed batches retained between COPY boundaries;
// it never changes the durable window, original batch IDs, or SQL transaction.
package recordingest

import (
	"context"
	"errors"
	"fmt"
	"runtime"
)

const (
	privateW256RSSTarget      uint64 = 4 << 30
	privateW256RSSPressure    uint64 = 3072 << 20
	privateW256ManagedPressure uint64 = 2560 << 20
	privateW256MinChunk              = 32768
)

type privateW256BudgetKey struct{}

type privateW256Budget struct {
	requested int
	active int
	maxRSS uint64
	maxManaged uint64
	pressureCuts int
	chunks int
}

// WithPrivateW256MemoryBudget is deliberately unavailable to ordinary FI
// ingestion: only the private W256 signed replay enables this optional soft
// memory budget. It DOES NOT promise a hard resident memory ceiling.
func WithPrivateW256MemoryBudget(ctx context.Context, requestedChunk int) (context.Context, error) {
	if ctx == nil {
		return nil, errors.New("FI W256 memory: nil context")
	}
	switch requestedChunk {
	case 32768, 65536, 98304, 131072:
	default:
		return nil, errors.New("FI W256 memory: unsupported processing chunk")
	}
	return context.WithValue(ctx, privateW256BudgetKey{}, &privateW256Budget{
		requested: requestedChunk, active: requestedChunk,
	}), nil
}

func privateW256BudgetFromContext(ctx context.Context) *privateW256Budget {
	if ctx == nil {
		return nil
	}
	b, _ := ctx.Value(privateW256BudgetKey{}).(*privateW256Budget)
	return b
}

// decideW256Memory is an advisory, measured soft-pressure signal.
// It closes the current COPY chunk at an intact signed-batch boundary and
// reduces subsequent chunk ceilings. If the host runs out of memory,
// the ordinary process/transaction failure and rollback behavior applies.
func decideW256Memory(rss, managed uint64) (pressure bool, err error) {
	return rss >= privateW256RSSPressure || managed >= privateW256ManagedPressure, nil
}

func (b *privateW256Budget) sample() (bool, error) {
	if b == nil {
		return false, nil
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	managed := m.Sys - m.HeapReleased // Go's actual GOMEMLIMIT accounting basis.
	rss, err := privateW256PeakRSSBytes()
	if err != nil {
		return false, fmt.Errorf("FI W256 memory: process RSS unavailable: %w", err)
	}
	if rss > b.maxRSS {
		b.maxRSS = rss
	}
	if managed > b.maxManaged {
		b.maxManaged = managed
	}
	return decideW256Memory(rss, managed)
}

func (b *privateW256Budget) afterChunk(pressure bool) {
	if b == nil {
		return
	}
	b.chunks++
	if pressure {
		b.pressureCuts++
		if b.active > privateW256MinChunk {
			b.active -= privateW256MinChunk
		}
	}
	// Deliberately no automatic growth within a signed W256 window.
	// Once memory pressure is observed, keep the smaller safe chunk.
}

func (b *privateW256Budget) summary() string {
	if b == nil {
		return "disabled"
	}
	return fmt.Sprintf("rss_target_bytes=%d enforcement=advisory requested_chunk=%d final_chunk_ceiling=%d chunks=%d memory_pressure_cuts=%d peak_rss_bytes=%d peak_go_managed_bytes=%d",
		privateW256RSSTarget, b.requested, b.active,
		b.chunks, b.pressureCuts, b.maxRSS, b.maxManaged)
}
