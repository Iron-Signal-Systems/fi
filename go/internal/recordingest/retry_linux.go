// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package recordingest

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// LoadDueSourceRecordRetryGenerationIDs returns a bounded, deterministic set of
// generations whose latest durable source-record rejection is due for retry.
// The append-only ingest journal is the retry authority; READY is not used for
// deferred retry scheduling.
func LoadDueSourceRecordRetryGenerationIDs(
	ctx context.Context,
	connection *pgx.Conn,
	sourceID string,
	dueBefore time.Time,
	limit uint64,
) ([]string, error) {
	if ctx == nil || connection == nil {
		return nil, errors.New("FI ingest retry connection is required")
	}
	if sourceID == "" {
		return nil, errors.New("FI ingest retry source ID is required")
	}
	if dueBefore.IsZero() {
		return nil, errors.New("FI ingest retry due-before time is required")
	}
	if limit == 0 {
		return nil, errors.New("FI ingest retry limit must be greater than zero")
	}
	if limit > uint64(^uint64(0)>>1) {
		return nil, errors.New("FI ingest retry limit exceeds PostgreSQL bigint bounds")
	}

	rows, err := connection.Query(
		ctx,
		`
WITH latest_rejection AS (
    SELECT
        generation_id,
        max(occurred_at) AS rejected_at
    FROM fi.ingest_journal
    WHERE source_id = $1
      AND generation_id IS NOT NULL
      AND outcome = 'Rejected'
      AND reason_code = 'SOURCE_RECORD_REJECTED'
    GROUP BY generation_id
)
SELECT
    latest_rejection.generation_id
FROM latest_rejection
WHERE latest_rejection.rejected_at <= $2
  AND NOT EXISTS (
      SELECT 1
      FROM fi.recorded_generation
      WHERE recorded_generation.source_id = $1
        AND recorded_generation.generation_id = latest_rejection.generation_id
  )
ORDER BY
    latest_rejection.rejected_at,
    latest_rejection.generation_id
LIMIT $3
`,
		sourceID,
		dueBefore,
		int64(limit),
	)
	if err != nil {
		return nil, fmt.Errorf("read FI due source-record retries: %w", err)
	}
	defer rows.Close()

	generationIDs := make([]string, 0)
	for rows.Next() {
		var generationID string
		if err := rows.Scan(&generationID); err != nil {
			return nil, fmt.Errorf("scan FI due source-record retry: %w", err)
		}
		generationIDs = append(generationIDs, generationID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate FI due source-record retries: %w", err)
	}

	return generationIDs, nil
}

// SourceRecordRejectionRecorded confirms that the exact ingest attempt has a
// durable terminal rejection row before READY may be retired. This prevents a
// failed journal write from silently losing the immediate retry locator.
func SourceRecordRejectionRecorded(
	ctx context.Context,
	connection *pgx.Conn,
	attemptID string,
	sourceID string,
	generationID string,
) (bool, error) {
	if ctx == nil || connection == nil {
		return false, errors.New("FI ingest rejection verification connection is required")
	}
	if attemptID == "" || sourceID == "" || generationID == "" {
		return false, errors.New("FI ingest rejection verification identity is incomplete")
	}

	var recorded bool
	if err := connection.QueryRow(
		ctx,
		`
SELECT EXISTS (
    SELECT 1
    FROM fi.ingest_journal
    WHERE attempt_id = $1
      AND event_sequence = 2
      AND source_id = $2
      AND generation_id = $3
      AND outcome = 'Rejected'
      AND stage = 'AuthoritativeRecord'
      AND reason_code = 'SOURCE_RECORD_REJECTED'
)
`,
		attemptID,
		sourceID,
		generationID,
	).Scan(&recorded); err != nil {
		return false, fmt.Errorf("verify FI durable source-record rejection: %w", err)
	}

	return recorded, nil
}
