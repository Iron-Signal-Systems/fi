// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

type boundaryLookupTestTx struct {
	pgx.Tx
	t   *testing.T
	row pgx.Row
}

func (tx *boundaryLookupTestTx) QueryRow(
	_ context.Context,
	sql string,
	args ...any,
) pgx.Row {
	tx.t.Helper()

	if len(args) != 3 ||
		args[0] != "source-a" ||
		args[1] != "scope-a" ||
		args[2] != int64(100) {
		tx.t.Fatalf("unexpected boundary arguments: %v", args)
	}

	normalized := strings.Join(strings.Fields(sql), " ")

	for _, required := range []string{
		"FROM fi.usn_read_boundary AS urb",
		"WHERE urb.source_record_id < $3",
		"rg.source_id = $1",
		"sr.scope_id = $2",
		"WHERE sr.source_record_id = urb.source_record_id",
		") IS TRUE",
		"ORDER BY urb.source_record_id DESC",
		"LIMIT 1",
	} {
		if !strings.Contains(normalized, required) {
			tx.t.Fatalf("boundary SQL missing %q", required)
		}
	}

	return tx.row
}

type boundaryLookupTestRow struct {
	boundaryID int64
	volumeID   int64
	err        error
}

func (row boundaryLookupTestRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}

	if len(dest) != 2 {
		return errors.New("expected two scan destinations")
	}

	boundary, ok := dest[0].(*int64)
	if !ok {
		return errors.New("invalid boundary destination")
	}

	volume, ok := dest[1].(*int64)
	if !ok {
		return errors.New("invalid volume destination")
	}

	*boundary = row.boundaryID
	*volume = row.volumeID
	return nil
}

func TestUSNPrecedingBoundaryLookupContract(t *testing.T) {
	tests := []struct {
		name      string
		row       boundaryLookupTestRow
		wantID    int64
		wantVol   int64
		wantError bool
	}{
		{
			name:    "matching preceding boundary",
			row:     boundaryLookupTestRow{boundaryID: 80, volumeID: 7},
			wantID:  80,
			wantVol: 7,
		},
		{
			name:      "no preceding boundary",
			row:       boundaryLookupTestRow{err: pgx.ErrNoRows},
			wantError: true,
		},
		{
			name:      "database failure",
			row:       boundaryLookupTestRow{err: errors.New("database unavailable")},
			wantError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tx := &boundaryLookupTestTx{
				t:   t,
				row: tc.row,
			}

			id, volume, err := findPrecedingUSNReadBoundary(
				context.Background(),
				tx,
				"source-a",
				"scope-a",
				100,
			)

			if (err != nil) != tc.wantError {
				t.Fatalf("unexpected boundary error: %v", err)
			}

			if !tc.wantError &&
				(id != tc.wantID || volume != tc.wantVol) {
				t.Fatalf(
					"boundary=(%d,%d), want=(%d,%d)",
					id, volume, tc.wantID, tc.wantVol,
				)
			}
		})
	}
}
