//go:build fi_file_observation_bulk_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestFileObservationBulkPostgreSQL(t *testing.T) {
	dsn := os.Getenv("FI_FILE_OBSERVATION_BULK_TEST_DSN")
	data := os.Getenv("FI_FILE_OBSERVATION_BULK_TEST_DATA")
	if dsn == "" || data == "" {
		t.Fatal("isolated PostgreSQL environment required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	var actual, listen, database string
	if err = conn.QueryRow(ctx, "SHOW data_directory").Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if err = conn.QueryRow(ctx, "SHOW listen_addresses").Scan(&listen); err != nil {
		t.Fatal(err)
	}
	if err = conn.QueryRow(ctx, "SELECT current_database()").Scan(&database); err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(actual) != filepath.Clean(data) || listen != "" || database != "fi_file_observation_bulk_test" {
		t.Fatalf("STOP: PostgreSQL isolation mismatch data=%q listener=%q database=%q", actual, listen, database)
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	ddl := []string{
		`CREATE SCHEMA fi`,
		`CREATE TABLE fi.source_record (source_record_id bigint PRIMARY KEY)`,
		`CREATE TABLE fi.governed_root (governed_root_id bigint PRIMARY KEY)`,
		`CREATE TABLE fi.ntfs_object (ntfs_object_id bigint PRIMARY KEY)`,
		`CREATE TABLE fi.file_observation (
            source_record_id bigint PRIMARY KEY REFERENCES fi.source_record,
            governed_root_id bigint NOT NULL REFERENCES fi.governed_root,
            ntfs_object_id bigint NOT NULL REFERENCES fi.ntfs_object,
            parent_state text NOT NULL,
            parent_ntfs_object_id bigint REFERENCES fi.ntfs_object,
            parent_reason_code text,
            subject_kind text NOT NULL,
            requested_path_utf16le bytea NOT NULL,
            resolved_path_utf16le bytea NOT NULL,
            observed_at timestamptz NOT NULL,
            containment_method_version text NOT NULL,
            collection_entry_method text NOT NULL,
            collection_method text NOT NULL,
            observation_status text NOT NULL)`,
		`CREATE TABLE fi.file_metadata_observation (
            source_record_id bigint PRIMARY KEY REFERENCES fi.file_observation,
            logical_size numeric(20,0) NOT NULL CHECK(logical_size>=0),
            allocated_size numeric(20,0) NOT NULL CHECK(allocated_size>=0),
            creation_time timestamptz NOT NULL,
            last_write_time timestamptz NOT NULL,
            change_time timestamptz NOT NULL,
            last_access_time timestamptz NOT NULL,
            raw_attributes bigint NOT NULL,
            link_count bigint NOT NULL)`,
		`INSERT INTO fi.source_record VALUES (501),(502)`,
		`INSERT INTO fi.governed_root VALUES (30)`,
		`INSERT INTO fi.ntfs_object VALUES (40)`,
	}
	for _, q := range ddl {
		if _, err := tx.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	row := func(id int64) fileObservationBulkPrepared {
		return fileObservationBulkPrepared{
			parent:   []any{id, int64(30), int64(40), "GovernedRoot", nil, nil, "File", []byte{1, 2}, []byte{3, 4}, now, "v1", "e1", "c1", "Complete"},
			metadata: []any{id, pgtype.Numeric{Int: big.NewInt(9), Exp: 0, Valid: true}, pgtype.Numeric{Int: big.NewInt(16), Exp: 0, Valid: true}, now, now, now, now, int64(32), int64(1)},
		}
	}
	rows := []fileObservationBulkPrepared{row(501), row(502)}
	if err := copyFileBulkRelationalRows(ctx, tx, rows, nil); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM fi.file_metadata_observation m JOIN fi.file_observation f USING(source_record_id)`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("file/metadata FK join count=%d want 2", count)
	}
	var size string
	if err := tx.QueryRow(ctx, `SELECT logical_size::text FROM fi.file_metadata_observation WHERE source_record_id=501`).Scan(&size); err != nil {
		t.Fatal(err)
	}
	if size != "9" {
		t.Fatalf("numeric size=%q", size)
	}

	// Duplicate parent and missing FK must fail without persisting a partial chunk.
	savepoint, err := tx.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := copyFileBulkRelationalRows(ctx, savepoint, []fileObservationBulkPrepared{row(501)}, nil); err == nil {
		t.Fatal("duplicate file parent accepted")
	}
	if err := savepoint.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM fi.file_metadata_observation`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("failed chunk changed committed rows: %d", count)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('fi.file_observation') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("test left durable schema behind")
	}
}
