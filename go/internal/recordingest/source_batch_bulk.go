// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const sourceBatchBulkMaxRecords = 512

// sourceBatchBulkProfile measures the two SQL stages independently from
// per-source-record preparation and relational projection.
type sourceBatchBulkProfile struct {
	Rows    int
	Copies  int
	Prepare time.Duration
	Copy    time.Duration
	Lookup  time.Duration
}

// copySourceBatches records the immutable manifest metadata using bounded COPY
// calls and maps the generated PostgreSQL identities back to receipt order.
//
// The caller owns the generation transaction. An error invalidates that
// transaction: neither the batch rows nor subsequent source records may commit.
// COPY never assumes identity values are consecutive or in receipt order.
func copySourceBatches(
	ctx context.Context,
	tx pgx.Tx,
	recordedGenerationID int64,
	batches []PreparedBatch,
	profile *sourceBatchBulkProfile,
) ([]int64, error) {
	if ctx == nil || tx == nil || profile == nil || recordedGenerationID <= 0 || len(batches) == 0 {
		return nil, errors.New("FI source-batch bulk inputs are incomplete")
	}

	// A new recorded-generation identity is inserted before this call. There
	// cannot be preexisting batches for it. Uniqueness is still enforced by
	// PostgreSQL and is checked here before any COPY begins.
	indices := make(map[string]int, len(batches))
	for i, batch := range batches {
		if batch.BatchID == "" || batch.BatchID != batch.Manifest.BatchID ||
			batch.ManifestArtifactName == "" || batch.DataArtifactName == "" ||
			batch.Manifest.DataFile != batch.DataArtifactName {
			return nil, fmt.Errorf("FI source-batch identity mismatch at index %d", i)
		}
		if _, exists := indices[batch.BatchID]; exists {
			return nil, fmt.Errorf("FI duplicate source-batch identity %q", batch.BatchID)
		}
		indices[batch.BatchID] = i
	}

	columns := []string{
		"recorded_generation_id", "manifest_artifact_name", "data_artifact_name", "manifest_version",
		"batch_id", "target_batch_size", "record_count", "data_bytes", "data_sha256",
		"data_file", "collector_executable_path", "collector_executable_sha256", "created_at",
		"completed_at", "manifest_bytes", "manifest_sha256",
	}

	for start := 0; start < len(batches); start += sourceBatchBulkMaxRecords {
		end := start + sourceBatchBulkMaxRecords
		if end > len(batches) {
			end = len(batches)
		}

		preparedAt := time.Now()
		values := make([][]any, 0, end-start)
		for i := start; i < end; i++ {
			row, err := prepareSourceBatchBulkRow(recordedGenerationID, batches[i])
			if err != nil {
				return nil, fmt.Errorf("prepare FI source batch %q: %w", batches[i].BatchID, err)
			}
			values = append(values, row)
		}
		profile.Prepare += time.Since(preparedAt)

		copyAt := time.Now()
		copied, err := tx.CopyFrom(
			ctx,
			pgx.Identifier{"fi", "source_batch"},
			columns,
			pgx.CopyFromRows(values),
		)
		profile.Copy += time.Since(copyAt)
		if err != nil {
			return nil, fmt.Errorf("COPY FI source batches %d-%d: %w", start, end, err)
		}
		if copied != int64(len(values)) {
			return nil, fmt.Errorf("FI source-batch COPY count mismatch: got %d expected %d", copied, len(values))
		}
		profile.Rows += len(values)
		profile.Copies++
	}

	// Resolve generated identities from the authoritative unique pair, not
	// from sequence arithmetic. The source_record FK and every projection
	// subsequently use these exact database-returned IDs.
	lookupAt := time.Now()
	rows, err := tx.Query(ctx, `
SELECT batch_id, source_batch_id
FROM fi.source_batch
WHERE recorded_generation_id = $1
ORDER BY batch_id
`, recordedGenerationID)
	if err != nil {
		return nil, fmt.Errorf("query FI source-batch identities: %w", err)
	}

	identities := make([]int64, len(batches))
	found := 0
	for rows.Next() {
		var batchID string
		var sourceBatchID int64
		if err := rows.Scan(&batchID, &sourceBatchID); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan FI source-batch identity: %w", err)
		}
		i, known := indices[batchID]
		if !known || sourceBatchID <= 0 || identities[i] != 0 {
			rows.Close()
			return nil, fmt.Errorf("FI source-batch identity lookup mismatch for %q", batchID)
		}
		identities[i] = sourceBatchID
		found++
	}
	readErr := rows.Err()
	rows.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read FI source-batch identities: %w", readErr)
	}
	if found != len(batches) {
		return nil, fmt.Errorf("FI source-batch identity count mismatch: got %d expected %d", found, len(batches))
	}
	profile.Lookup += time.Since(lookupAt)

	return identities, nil
}

// prepareSourceBatchBulkRow retains the exact deployed source_batch columns
// and validates decoded digests/timestamps before passing values to PostgreSQL.
func prepareSourceBatchBulkRow(recordedGenerationID int64, batch PreparedBatch) ([]any, error) {
	manifest := batch.Manifest
	dataSHA, err := decodeHex(manifest.DataSHA256, 32, true, "source_batch.data_sha256")
	if err != nil {
		return nil, err
	}
	collectorSHA, err := decodeHex(manifest.Collector.ExecutableSHA256, 32, true, "source_batch.collector_sha256")
	if err != nil {
		return nil, err
	}
	manifestSHA, err := decodeHex(batch.ManifestSHA256, 32, true, "source_batch.manifest_sha256")
	if err != nil {
		return nil, err
	}
	createdAt, err := parseRFC3339(manifest.CreatedAt, "source_batch.created_at")
	if err != nil {
		return nil, err
	}
	completedAt, err := parseRFC3339(manifest.CompletedAt, "source_batch.completed_at")
	if err != nil {
		return nil, err
	}

	return []any{
		recordedGenerationID, batch.ManifestArtifactName, batch.DataArtifactName,
		manifest.Version, manifest.BatchID, manifest.TargetBatchSize,
		int64(manifest.RecordCount), manifest.DataBytes, dataSHA,
		manifest.DataFile, manifest.Collector.ExecutablePath, collectorSHA,
		createdAt, completedAt, int64(batch.ManifestBytes), manifestSHA,
	}, nil
}
