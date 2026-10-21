//go:build fi_file_source_copy_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/jackc/pgx/v5"
)

func TestFileSourceBulkPostgreSQL(t *testing.T) {
	dsn := os.Getenv("FI_FILE_SOURCE_COPY_TEST_DSN")
	expected := os.Getenv("FI_FILE_SOURCE_COPY_TEST_DATA")
	if dsn == "" || expected == "" {
		t.Fatal("isolated PostgreSQL source COPY test configuration is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())

	var dataDir, listenAddresses, database string
	if err := conn.QueryRow(ctx, "SHOW data_directory").Scan(&dataDir); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, "SHOW listen_addresses").Scan(&listenAddresses); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, "SELECT current_database()").Scan(&database); err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(dataDir) != filepath.Clean(expected) || listenAddresses != "" || database != "fi_file_source_bulk_test" {
		t.Fatalf("refusing non-isolated PostgreSQL destination: data=%q listen=%q db=%q", dataDir, listenAddresses, database)
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	ddl := []string{
		`CREATE SCHEMA fi`,
		`CREATE TABLE fi.source_batch (source_batch_id bigint PRIMARY KEY)`,
		`CREATE TABLE fi.source_record (
            source_record_id bigint GENERATED ALWAYS AS IDENTITY (START WITH 101 INCREMENT BY 7) PRIMARY KEY,
            source_batch_id bigint NOT NULL REFERENCES fi.source_batch,
            record_ordinal bigint NOT NULL,
            version text NOT NULL,
            record_kind text NOT NULL,
            scope_id text NOT NULL,
            written_at timestamptz NOT NULL,
            record_bytes integer NOT NULL,
            record_sha256 bytea NOT NULL CHECK (octet_length(record_sha256) = 32),
            ingest_version text NOT NULL,
            UNIQUE (source_batch_id, record_ordinal))`,
		`INSERT INTO fi.source_batch VALUES (41), (42)`,
	}
	for _, sql := range ddl {
		if _, err := tx.Exec(ctx, sql); err != nil {
			t.Fatalf("initialize isolated test schema: %v", err)
		}
	}

	makeRecord := func(ordinal int64) fileSourceBulkRecord {
		digest := bytes.Repeat([]byte{byte(ordinal)}, 32)
		return fileSourceBulkRecord{
			ordinal: ordinal, digest: digest,
			prepared: SourceRecord{
				Record:       spool.Record{Version: SpoolRecordVersion, RecordKind: "FileObservation", ScopeID: "scope-a"},
				WrittenAtUTC: time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC),
				RecordBytes:  100 + int(ordinal),
			},
		}
	}

	pending := []fileSourceBulkRecord{makeRecord(1), makeRecord(2), makeRecord(3)}
	profile := &ingestStageProfile{}
	if err := copyFileSourceBulk(ctx, tx, 41, pending, profile); err != nil {
		t.Fatal(err)
	}
	if pending[0].sourceRecordID != 101 || pending[1].sourceRecordID != 108 || pending[2].sourceRecordID != 115 {
		t.Fatalf("COPY must return actual sequence IDs: %d %d %d", pending[0].sourceRecordID, pending[1].sourceRecordID, pending[2].sourceRecordID)
	}
	if profile.SourceSQL <= 0 {
		t.Fatal("source COPY timing missing")
	}

	rows, err := tx.Query(ctx, `SELECT record_ordinal,source_record_id,record_sha256,record_kind,record_bytes
        FROM fi.source_record WHERE source_batch_id=41 ORDER BY record_ordinal`)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for rows.Next() {
		var ordinal, id int64
		var digest []byte
		var kind string
		var recordBytes int
		if err := rows.Scan(&ordinal, &id, &digest, &kind, &recordBytes); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if count >= len(pending) || ordinal != pending[count].ordinal || id != pending[count].sourceRecordID ||
			!bytes.Equal(digest, pending[count].digest) || kind != "FileObservation" || recordBytes != pending[count].prepared.RecordBytes {
			rows.Close()
			t.Fatalf("source COPY lineage mismatch at index %d", count)
		}
		count++
	}
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil {
		t.Fatal(rowErr)
	}
	if count != len(pending) {
		t.Fatalf("expected %d source records, got %d", len(pending), count)
	}

	other := []fileSourceBulkRecord{makeRecord(1)}
	if err := copyFileSourceBulk(ctx, tx, 42, other, profile); err != nil {
		t.Fatal(err)
	}
	if other[0].sourceRecordID <= pending[2].sourceRecordID {
		t.Fatal("distinct batch source identity was not allocated")
	}

	// Bad input must fail before issuing COPY.
	unordered := []fileSourceBulkRecord{makeRecord(6), makeRecord(8)}
	if err := copyFileSourceBulk(ctx, tx, 41, unordered, profile); err == nil {
		t.Fatal("unordered ordinals accepted")
	}
	if err := copyFileSourceBulk(ctx, tx, 41, []fileSourceBulkRecord{{ordinal: 9}}, profile); err == nil {
		t.Fatal("invalid envelope accepted")
	}

	// A unique-key failure inside a savepoint must not leave partial source rows.
	subtx, err := tx.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := copyFileSourceBulk(ctx, subtx, 41, []fileSourceBulkRecord{makeRecord(3)}, profile); err == nil {
		_ = subtx.Rollback(context.Background())
		t.Fatal("duplicate source ordinal accepted")
	}
	if err := subtx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var persisted int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM fi.source_record WHERE source_batch_id=41`).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if persisted != 3 {
		t.Fatalf("COPY error leaked rows; got %d", persisted)
	}

	// Roll back schema and data together: this test has no durable side effects.
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var relationExists bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('fi.source_record') IS NOT NULL`).Scan(&relationExists); err != nil {
		t.Fatal(err)
	}
	if relationExists {
		t.Fatal("test rollback left relational table")
	}
}
