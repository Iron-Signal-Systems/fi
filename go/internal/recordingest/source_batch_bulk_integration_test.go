// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build fi_source_batch_bulk_integration

package recordingest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestSourceBatchBulkPostgreSQL accepts only an explicitly supplied, isolated
// PostgreSQL cluster and rolls its test schema back before returning.
func TestSourceBatchBulkPostgreSQL(t *testing.T) {
	dsn := os.Getenv("FI_SOURCE_BATCH_BULK_TEST_DSN")
	expected := os.Getenv("FI_SOURCE_BATCH_BULK_TEST_DATA")
	if dsn == "" || expected == "" {
		t.Fatal("isolated PostgreSQL configuration required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())

	var directory, listen string
	if err := conn.QueryRow(ctx, "SHOW data_directory").Scan(&directory); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, "SHOW listen_addresses").Scan(&listen); err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(directory) != filepath.Clean(expected) || listen != "" {
		t.Fatalf("STOP: unexpected PostgreSQL server: %q %q", directory, listen)
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())

	for _, statement := range []string{
		`CREATE SCHEMA fi`,
		`CREATE TABLE fi.recorded_generation (recorded_generation_id bigint PRIMARY KEY)`,
		`CREATE TABLE fi.source_batch (
source_batch_id bigint GENERATED ALWAYS AS IDENTITY
    (START WITH 101 INCREMENT BY 7) PRIMARY KEY,
recorded_generation_id bigint NOT NULL REFERENCES fi.recorded_generation,
manifest_artifact_name text NOT NULL,
data_artifact_name text NOT NULL,
manifest_version text NOT NULL,
batch_id text NOT NULL,
target_batch_size integer NOT NULL CHECK (target_batch_size > 0),
record_count bigint NOT NULL CHECK (record_count > 0),
data_bytes bigint NOT NULL CHECK (data_bytes > 0),
data_sha256 bytea NOT NULL CHECK (octet_length(data_sha256) = 32),
data_file text NOT NULL,
collector_executable_path text NOT NULL,
collector_executable_sha256 bytea NOT NULL CHECK (octet_length(collector_executable_sha256) = 32),
created_at timestamptz NOT NULL,
completed_at timestamptz NOT NULL,
manifest_bytes bigint NOT NULL CHECK (manifest_bytes > 0),
manifest_sha256 bytea NOT NULL CHECK (octet_length(manifest_sha256) = 32),
ingested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
UNIQUE (recorded_generation_id, batch_id),
UNIQUE (recorded_generation_id, manifest_artifact_name),
UNIQUE (recorded_generation_id, data_artifact_name)
)`,
		`INSERT INTO fi.recorded_generation VALUES (44)`,
	} {
		if _, err := tx.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}

	batches := make([]PreparedBatch, 513)
	for i := range batches {
		batches[i] = newSourceBatchBulkTestBatch(fmt.Sprintf("b-%05d", i))
	}
	var profile sourceBatchBulkProfile
	identities, err := copySourceBatches(ctx, tx, 44, batches, &profile)
	if err != nil {
		t.Fatal(err)
	}
	if len(identities) != 513 || profile.Rows != 513 || profile.Copies != 2 {
		t.Fatalf("bulk result mismatch: ids=%d rows=%d copies=%d", len(identities), profile.Rows, profile.Copies)
	}
	for i, id := range identities {
		if want := int64(101 + i*7); id != want {
			t.Fatalf("generated ID mapping[%d] = %d, want %d", i, id, want)
		}
	}

	var count int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM fi.source_batch").Scan(&count); err != nil || count != 513 {
		t.Fatalf("source batch count = %d, error = %v", count, err)
	}

	// Input duplicates are rejected before COPY rather than depending on a
	// database failure halfway through the transaction.
	bad := []PreparedBatch{batches[0], batches[0]}
	if _, err := copySourceBatches(ctx, tx, 44, bad, &sourceBatchBulkProfile{}); err == nil {
		t.Fatal("duplicate immutable batch identity accepted")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var absent bool
	if err := conn.QueryRow(ctx, "SELECT to_regclass('fi.source_batch') IS NULL").Scan(&absent); err != nil || !absent {
		t.Fatalf("test data survived rollback: absent=%v error=%v", absent, err)
	}
}
