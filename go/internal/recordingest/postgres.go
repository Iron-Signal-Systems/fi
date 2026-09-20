// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

const DefaultPostgreSQLConnectionString = "host=/run/postgresql dbname=fi user=fi_ingest sslmode=disable"

const expectedRelationalTableCount = 49

type PostgreSQLState struct {
	CurrentDatabase  string
	CurrentUser      string
	RelationalTables int
}

func OpenPostgreSQL(ctx context.Context, connectionString string) (*pgx.Conn, PostgreSQLState, error) {
	if ctx == nil {
		return nil, PostgreSQLState{}, errors.New("FI PostgreSQL context is required")
	}
	if connectionString == "" {
		return nil, PostgreSQLState{}, errors.New("FI PostgreSQL connection string is required")
	}

	connection, err := pgx.Connect(ctx, connectionString)
	if err != nil {
		return nil, PostgreSQLState{}, fmt.Errorf("connect FI PostgreSQL: %w", err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = connection.Close(context.Background())
		}
	}()

	var state PostgreSQLState
	if err := connection.QueryRow(ctx, `SELECT current_user, current_database()`).Scan(&state.CurrentUser, &state.CurrentDatabase); err != nil {
		return nil, PostgreSQLState{}, fmt.Errorf("read FI PostgreSQL runtime identity: %w", err)
	}
	if state.CurrentUser != "fi_ingest" {
		return nil, PostgreSQLState{}, fmt.Errorf("FI PostgreSQL runtime user is %q, expected %q", state.CurrentUser, "fi_ingest")
	}
	if state.CurrentDatabase != "fi" {
		return nil, PostgreSQLState{}, fmt.Errorf("FI PostgreSQL database is %q, expected %q", state.CurrentDatabase, "fi")
	}

	if err := verifyPostgreSQLRelationalFoundation(ctx, connection, &state); err != nil {
		return nil, PostgreSQLState{}, err
	}

	closeOnError = false
	return connection, state, nil
}

func verifyPostgreSQLRelationalFoundation(ctx context.Context, connection *pgx.Conn, state *PostgreSQLState) error {
	if connection == nil {
		return errors.New("FI PostgreSQL connection is required")
	}
	if state == nil {
		return errors.New("FI PostgreSQL state is required")
	}

	var (
		tableCount      int
		badTypedColumns int
		missingCore     int
		canUpdate       bool
		canDelete       bool
		canTruncate     bool
	)

	if err := connection.QueryRow(ctx, `
SELECT count(*)::int
FROM information_schema.tables
WHERE table_schema = 'fi'
  AND table_type = 'BASE TABLE'
`).Scan(&tableCount); err != nil {
		return fmt.Errorf("count FI relational tables: %w", err)
	}
	if tableCount != expectedRelationalTableCount {
		return fmt.Errorf("FI PostgreSQL relational table count is %d, expected %d", tableCount, expectedRelationalTableCount)
	}

	if err := connection.QueryRow(ctx, `
SELECT count(*)::int
FROM information_schema.columns
WHERE table_schema = 'fi'
  AND data_type IN ('json','jsonb','xml')
`).Scan(&badTypedColumns); err != nil {
		return fmt.Errorf("verify FI relational column types: %w", err)
	}
	if badTypedColumns != 0 {
		return fmt.Errorf("FI PostgreSQL contains %d JSON/JSONB/XML columns; expected none", badTypedColumns)
	}

	if err := connection.QueryRow(ctx, `
SELECT count(*)::int
FROM (VALUES
    ('recorded_generation'),
    ('source_batch'),
    ('source_record'),
    ('ingest_journal'),
    ('ntfs_volume'),
    ('ntfs_object'),
    ('governed_root'),
    ('file_observation'),
    ('usn_read_boundary'),
    ('usn_object_observation'),
    ('usn_object_change'),
    ('windows_security_event')
) AS required(table_name)
WHERE to_regclass('fi.' || required.table_name) IS NULL
`).Scan(&missingCore); err != nil {
		return fmt.Errorf("verify FI relational core tables: %w", err)
	}
	if missingCore != 0 {
		return fmt.Errorf("FI PostgreSQL relational foundation is missing %d required core tables", missingCore)
	}

	if err := connection.QueryRow(ctx, `
SELECT
    has_table_privilege(current_user, 'fi.source_record', 'UPDATE'),
    has_table_privilege(current_user, 'fi.source_record', 'DELETE'),
    has_table_privilege(current_user, 'fi.source_record', 'TRUNCATE')
`).Scan(&canUpdate, &canDelete, &canTruncate); err != nil {
		return fmt.Errorf("verify FI append-only runtime boundary: %w", err)
	}
	if canUpdate || canDelete || canTruncate {
		return errors.New("FI PostgreSQL runtime identity has mutation authority over source_record")
	}

	state.RelationalTables = tableCount
	return nil
}
