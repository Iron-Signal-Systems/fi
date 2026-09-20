// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"fmt"

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
