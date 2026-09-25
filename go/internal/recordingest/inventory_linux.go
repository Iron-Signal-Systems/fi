// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package recordingest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/jackc/pgx/v5"
)

type RecordKindCount struct {
	Count uint64
	Kind  string
}

type GenerationKindInventory struct {
	Candidate  RecordedReceiptCandidate
	DataBytes  uint64
	KindCounts []RecordKindCount
	Records    uint64
}

type PendingInventory struct {
	AuthoritativeKindCounts []RecordKindCount
	Conflict                uint64
	CoverageKindCounts      []RecordKindCount
	Discovered              uint64
	Inspected               uint64
	Items                   []GenerationKindInventory
	MissingKinds            []string
	Pending                 uint64
	SkippedAccepted         uint64
}

// InventoryPendingRecordedGenerations is a read-only corpus coverage pass. It
// starts at immutable recorder receipts, uses the relational plan to skip
// already-authoritative generations, reopens pending generations through the
// exact LoadRecordedGeneration custody/trust/semantic path, and parses source
// records with PrepareSourceRecord. It performs no PostgreSQL writes.
func InventoryPendingRecordedGenerations(
	ctx context.Context,
	connection *pgx.Conn,
	baseConfig GenerationLoadConfig,
	sourceFilter string,
	maxInspect uint64,
	stopWhenCovered bool,
) (PendingInventory, error) {
	if ctx == nil {
		return PendingInventory{}, errors.New("FI Phase 3 inventory context is required")
	}
	if connection == nil {
		return PendingInventory{}, errors.New("FI Phase 3 PostgreSQL connection is required")
	}

	plan, err := PlanRecordedGenerations(ctx, connection, baseConfig.RecordedRoot, sourceFilter)
	if err != nil {
		return PendingInventory{}, err
	}

	result := PendingInventory{
		Conflict:        plan.Conflict,
		Discovered:      plan.Discovered,
		Items:           make([]GenerationKindInventory, 0),
		Pending:         plan.Pending,
		SkippedAccepted: plan.Accepted,
	}

	authoritative, err := authoritativeRecordKindCounts(ctx, connection, sourceFilter)
	if err != nil {
		return result, err
	}
	result.AuthoritativeKindCounts = sortedKindCounts(authoritative)

	coverage := make(map[string]uint64, len(authoritative))
	for kind, count := range authoritative {
		coverage[kind] = count
	}

	if plan.Conflict != 0 {
		result.CoverageKindCounts = sortedKindCounts(coverage)
		result.MissingKinds = missingSupportedKinds(coverage)
		return result, fmt.Errorf(
			"FI Phase 3 inventory refuses to inspect pending custody while %d recorder/database conflict candidate(s) exist",
			plan.Conflict,
		)
	}

	for _, item := range plan.Items {
		if item.State != ReconcileStatePending {
			continue
		}
		if maxInspect != 0 && result.Inspected >= maxInspect {
			break
		}
		if stopWhenCovered && allSupportedKindsCovered(coverage) {
			break
		}

		config := baseConfig
		config.SourceID = item.Candidate.SourceID

		generation, err := LoadRecordedGeneration(config, item.Candidate.GenerationID)
		if err != nil {
			return result, fmt.Errorf(
				"inventory source=%q generation=%q: %w",
				item.Candidate.SourceID,
				item.Candidate.GenerationID,
				err,
			)
		}

		counts, records, dataBytes, inspectErr := InspectPreparedGenerationKinds(generation)
		closeErr := generation.Close()
		if err := errors.Join(inspectErr, closeErr); err != nil {
			return result, fmt.Errorf(
				"inventory source=%q generation=%q: %w",
				item.Candidate.SourceID,
				item.Candidate.GenerationID,
				err,
			)
		}

		for kind, count := range counts {
			coverage[kind] += count
		}

		result.Items = append(result.Items, GenerationKindInventory{
			Candidate:  item.Candidate,
			DataBytes:  dataBytes,
			KindCounts: sortedKindCounts(counts),
			Records:    records,
		})
		result.Inspected++
	}

	result.CoverageKindCounts = sortedKindCounts(coverage)
	result.MissingKinds = missingSupportedKinds(coverage)
	return result, nil
}

// InspectPreparedGenerationKinds validates every exact LF-terminated source
// record through PrepareSourceRecord and returns kind counts. LoadRecordedGeneration
// already established recorder/custody/trust/manifest integrity; this function
// adds the same stable source-envelope validation used by relational ingest.
func InspectPreparedGenerationKinds(generation *PreparedGeneration) (map[string]uint64, uint64, uint64, error) {
	if generation == nil {
		return nil, 0, 0, errors.New("FI Phase 3 prepared generation is required")
	}

	counts := make(map[string]uint64)
	var generationRecords uint64
	var generationBytes uint64

	for _, batch := range generation.Batches {
		file, err := os.Open(batch.DataPath)
		if err != nil {
			return nil, generationRecords, generationBytes, fmt.Errorf("open FI inventory source batch: %w", err)
		}

		reader := bufio.NewReader(file)
		var batchRecords uint64
		var batchBytes uint64

		for {
			raw, readErr := reader.ReadBytes('\n')
			if len(raw) == 0 && errors.Is(readErr, io.EOF) {
				break
			}
			if len(raw) == 0 && readErr != nil {
				_ = file.Close()
				return nil, generationRecords, generationBytes, fmt.Errorf("read FI inventory source batch: %w", readErr)
			}

			prepared, err := PrepareSourceRecord(raw)
			if err != nil {
				_ = file.Close()
				return nil, generationRecords, generationBytes, fmt.Errorf(
					"validate FI inventory source batch %q record %d: %w",
					batch.BatchID,
					batchRecords+1,
					err,
				)
			}

			batchRecords++
			batchBytes += uint64(len(raw))
			generationRecords++
			generationBytes += uint64(len(raw))
			counts[prepared.Record.RecordKind]++

			if readErr != nil {
				_ = file.Close()
				return nil, generationRecords, generationBytes, fmt.Errorf(
					"FI inventory source batch %q ended without exact LF framing: %w",
					batch.BatchID,
					readErr,
				)
			}
		}

		closeErr := file.Close()
		if closeErr != nil {
			return nil, generationRecords, generationBytes, fmt.Errorf("close FI inventory source batch: %w", closeErr)
		}
		if batchRecords != uint64(batch.Manifest.RecordCount) || int64(batchBytes) != batch.Manifest.DataBytes {
			return nil, generationRecords, generationBytes, fmt.Errorf(
				"FI inventory source batch %q changed after custody validation: records=%d/%d bytes=%d/%d",
				batch.BatchID,
				batchRecords,
				batch.Manifest.RecordCount,
				batchBytes,
				batch.Manifest.DataBytes,
			)
		}
	}

	if generationRecords != generation.Receipt.RecordCount || generationBytes != generation.Receipt.DataBytes {
		return nil, generationRecords, generationBytes, fmt.Errorf(
			"FI inventory generation totals differ from immutable recorder receipt: records=%d/%d bytes=%d/%d",
			generationRecords,
			generation.Receipt.RecordCount,
			generationBytes,
			generation.Receipt.DataBytes,
		)
	}

	return counts, generationRecords, generationBytes, nil
}

func authoritativeRecordKindCounts(ctx context.Context, connection *pgx.Conn, sourceFilter string) (map[string]uint64, error) {
	rows, err := connection.Query(ctx, `
SELECT sr.record_kind, count(*)::bigint
FROM fi.source_record sr
JOIN fi.source_batch sb
  ON sb.source_batch_id = sr.source_batch_id
JOIN fi.recorded_generation rg
  ON rg.recorded_generation_id = sb.recorded_generation_id
WHERE $1 = '' OR rg.source_id = $1
GROUP BY sr.record_kind
ORDER BY sr.record_kind
`, sourceFilter)
	if err != nil {
		return nil, fmt.Errorf("read FI authoritative record-kind counts: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]uint64)
	for rows.Next() {
		var kind string
		var count int64
		if err := rows.Scan(&kind, &count); err != nil {
			return nil, fmt.Errorf("scan FI authoritative record-kind count: %w", err)
		}
		if count < 0 {
			return nil, errors.New("FI authoritative record-kind count is negative")
		}
		counts[kind] = uint64(count)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read FI authoritative record-kind counts: %w", err)
	}
	return counts, nil
}

func sortedKindCounts(counts map[string]uint64) []RecordKindCount {
	kinds := make([]string, 0, len(counts))
	for kind := range counts {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)

	result := make([]RecordKindCount, 0, len(kinds))
	for _, kind := range kinds {
		result = append(result, RecordKindCount{Kind: kind, Count: counts[kind]})
	}
	return result
}

func missingSupportedKinds(counts map[string]uint64) []string {
	missing := make([]string, 0)
	for _, kind := range SupportedRecordKinds() {
		if counts[kind] == 0 {
			missing = append(missing, kind)
		}
	}
	sort.Strings(missing)
	return missing
}

func allSupportedKindsCovered(counts map[string]uint64) bool {
	return len(missingSupportedKinds(counts)) == 0
}
