// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type JournalEvent struct {
	AttemptID        string
	EventSequence    int
	SourceID         string
	GenerationID     string
	TransferSHA256   string
	Outcome          string
	Stage            string
	ReasonCode       string
	Detail           string
	RecordsSeen      *int64
	RecordsCommitted *int64
}

// LoadSourceRecordRejectionTimes returns the latest durable source-record
// rejection time for each requested pending generation. The append-only ingest
// journal remains the retry-state authority; no second mutable state store is
// introduced.
func LoadSourceRecordRejectionTimes(
	ctx context.Context,
	connection *pgx.Conn,
	sourceID string,
	generationIDs []string,
) (
	map[string]time.Time,
	error,
) {
	if ctx == nil || connection == nil {
		return nil, fmt.Errorf(
			"FI ingest journal connection is required",
		)
	}

	if sourceID == "" {
		return nil, fmt.Errorf(
			"FI ingest journal source ID is required",
		)
	}

	rejections :=
		make(map[string]time.Time)

	if len(generationIDs) == 0 {
		return rejections, nil
	}

	rows, err :=
		connection.Query(
			ctx,
			`
SELECT
    generation_id,
    max(occurred_at)
FROM fi.ingest_journal
WHERE source_id = $1
  AND generation_id = ANY($2::text[])
  AND outcome = 'Rejected'
  AND reason_code = 'SOURCE_RECORD_REJECTED'
GROUP BY generation_id
`,
			sourceID,
			generationIDs,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"read FI durable source-record rejection state: %w",
			err,
		)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			generationID string
			rejectedAt   time.Time
		)

		if err :=
			rows.Scan(
				&generationID,
				&rejectedAt,
			); err != nil {
			return nil, fmt.Errorf(
				"scan FI durable source-record rejection state: %w",
				err,
			)
		}

		rejections[generationID] =
			rejectedAt
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf(
			"iterate FI durable source-record rejection state: %w",
			err,
		)
	}

	return rejections, nil
}

func WriteAttemptStarted(ctx context.Context, connection *pgx.Conn, attemptID string, sourceID string, generationID string) error {
	zero := int64(0)
	return writeJournalEvent(ctx, connection, JournalEvent{
		AttemptID: attemptID, EventSequence: 1, SourceID: sourceID, GenerationID: generationID,
		Outcome: "Incomplete", Stage: "AttemptStarted", ReasonCode: "ATTEMPT_STARTED",
		RecordsSeen: &zero, RecordsCommitted: &zero,
	})
}

func WriteAttemptTerminal(ctx context.Context, connection *pgx.Conn, event JournalEvent) error {
	if event.EventSequence == 0 {
		event.EventSequence = 2
	}
	return writeJournalEvent(ctx, connection, event)
}

func writeJournalEvent(ctx context.Context, connection *pgx.Conn, event JournalEvent) error {
	if ctx == nil || connection == nil {
		return fmt.Errorf("FI ingest journal connection is required")
	}
	if event.AttemptID == "" || event.EventSequence <= 0 || event.Outcome == "" || event.Stage == "" {
		return fmt.Errorf("FI ingest journal event is incomplete")
	}
	transfer, err := decodeHex(event.TransferSHA256, 32, false, "ingest_journal.transfer_sha256")
	if err != nil {
		return err
	}
	_, err = connection.Exec(ctx, `
INSERT INTO fi.ingest_journal (
 attempt_id,event_sequence,source_id,generation_id,transfer_sha256,outcome,stage,reason_code,detail,records_seen,records_committed,ingest_version
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
`, event.AttemptID, event.EventSequence, nullString(event.SourceID), nullString(event.GenerationID), transfer, event.Outcome, event.Stage,
		nullString(event.ReasonCode), nullString(event.Detail), journalInt64(event.RecordsSeen), journalInt64(event.RecordsCommitted), IngestVersion)
	if err != nil {
		return fmt.Errorf("write FI ingest journal event: %w", err)
	}
	return nil
}

func journalInt64(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}
