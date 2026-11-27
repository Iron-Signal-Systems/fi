// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// Maximum unique relation identities observed in a single FI generation.
// FI's relational schema currently has 49 tables; this bounded array also
// handles a future table without allowing unbounded telemetry allocations.
const ingestCopyTableLimit = 64

// ingestCopyTableCounters track the complete pgx.CopyFrom call, including
// client encoding, PostgreSQL execution and waiting for the server. None of
// these values measures pure disk I/O or committed records by itself.
type ingestCopyTableCounters struct {
	table   string
	calls   int64
	rows    int64
	failed  int64
	total   time.Duration
	min     time.Duration
	max     time.Duration
	ge100ms int64
	ge500ms int64
	ge1s    int64
}

// ingestCopyMetrics is owned exclusively by the synchronous transaction
// goroutine. The read-only progress heartbeat must never read it directly.
type ingestCopyMetrics struct {
	tables   [ingestCopyTableLimit]ingestCopyTableCounters
	used     int
	overflow ingestCopyTableCounters
}

func newIngestCopyMetrics() *ingestCopyMetrics {
	return &ingestCopyMetrics{overflow: ingestCopyTableCounters{table: "_overflow"}}
}

func (m *ingestCopyMetrics) record(table pgx.Identifier, rows int64, elapsed time.Duration, err error) {
	if m == nil {
		return
	}
	// All callsites use schema-qualified constant table identifiers. Group by
	// their complete identifier so an unexpected schema cannot be conflated.
	name := "_invalid_identifier"
	if len(table) == 2 && table[0] != "" && table[1] != "" {
		name = table[0] + "." + table[1]
	}
	var slot *ingestCopyTableCounters
	for i := 0; i < m.used; i++ {
		if m.tables[i].table == name {
			slot = &m.tables[i]
			break
		}
	}
	if slot == nil {
		if m.used >= len(m.tables) {
			slot = &m.overflow
		} else {
			slot = &m.tables[m.used]
			slot.table = name
			m.used++
		}
	}
	if elapsed < 0 {
		elapsed = 0
	}
	if slot.calls == 0 || elapsed < slot.min {
		slot.min = elapsed
	}
	if elapsed > slot.max {
		slot.max = elapsed
	}
	slot.calls++
	slot.total += elapsed
	if err != nil {
		slot.failed++
	} else if rows > 0 {
		slot.rows += rows // Returned by completed COPY; not yet committed.
	}
	if elapsed >= 100*time.Millisecond {
		slot.ge100ms++
	}
	if elapsed >= 500*time.Millisecond {
		slot.ge500ms++
	}
	if elapsed >= time.Second {
		slot.ge1s++
	}
}

// top3 is used only on the ingest goroutine at the already-bounded progress
// snapshot checkpoint. These durations overlap the existing stage counters.
func (m *ingestCopyMetrics) top3() string {
	if m == nil || m.used == 0 {
		return "none"
	}
	var best [3]*ingestCopyTableCounters
	for i := 0; i < m.used; i++ {
		candidate := &m.tables[i]
		for pos := range best {
			if best[pos] == nil || candidate.total > best[pos].total {
				for j := len(best) - 1; j > pos; j-- {
					best[j] = best[j-1]
				}
				best[pos] = candidate
				break
			}
		}
	}
	result := ""
	for _, entry := range best {
		if entry == nil {
			continue
		}
		if result != "" {
			result += ","
		}
		result += fmt.Sprintf("%s:%s:%d", entry.table, entry.total.Round(time.Millisecond), entry.calls)
	}
	return result
}

// report emits one bounded and deterministic per-relation summary when the
// generation ends, whether accepted or uncommitted. It never reports a row as
// committed before the existing transaction has successfully committed.
func (m *ingestCopyMetrics) report(out io.Writer, source, generation, outcome string) {
	if m == nil || out == nil {
		return
	}
	list := make([]ingestCopyTableCounters, 0, m.used+1)
	list = append(list, m.tables[:m.used]...)
	if m.overflow.calls > 0 {
		list = append(list, m.overflow)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].total == list[j].total {
			return list[i].table < list[j].table
		}
		return list[i].total > list[j].total
	})
	for _, item := range list {
		avg := time.Duration(0)
		if item.calls > 0 {
			avg = item.total / time.Duration(item.calls)
		}
		fmt.Fprintf(out,
			"INGEST COPY TABLE source=%s generation=%s outcome=%s table=%s calls=%d rows_reported=%d errors=%d total=%s avg=%s min=%s max=%s ge_100ms=%d ge_500ms=%d ge_1s=%d\n",
			source, generation, outcome, item.table, item.calls, item.rows, item.failed,
			item.total.Round(time.Millisecond), avg.Round(time.Millisecond),
			item.min.Round(time.Millisecond), item.max.Round(time.Millisecond),
			item.ge100ms, item.ge500ms, item.ge1s,
		)
	}
}

// profiledIngestTx is a strict delegating adapter. It does not batch,
// reorder, alter, replay or retry COPY calls, nor change transaction scope.
// pgx.Tx embedding forwards Begin, Commit, Rollback, Query, QueryRow, Exec,
// SendBatch and every other method unchanged to the original transaction.
type profiledIngestTx struct {
	pgx.Tx
	metrics *ingestCopyMetrics
}

func (tx *profiledIngestTx) CopyFrom(ctx context.Context, table pgx.Identifier,
	columns []string, rows pgx.CopyFromSource) (int64, error) {
	started := time.Now()
	copied, err := tx.Tx.CopyFrom(ctx, table, columns, rows)
	tx.metrics.record(table, copied, time.Since(started), err)
	return copied, err
}
