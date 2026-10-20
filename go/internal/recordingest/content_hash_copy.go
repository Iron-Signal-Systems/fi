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

const (
	contentHashCopyMaxRows  = 1024
	contentHashCopyMaxBytes = 2 << 20
)

type contentHashCopyContextKey struct{}

type contentHashCopyState struct {
	rows     [][]any
	bytes    int
	copied   int64
	calls    int64
	duration time.Duration
}

func newContentHashCopyState() *contentHashCopyState {
	return &contentHashCopyState{}
}

func (s *contentHashCopyState) add(
	ctx context.Context, tx pgx.Tx, row []any,
) error {
	if len(row) != 8 {
		return fmt.Errorf("FI content hash COPY row has %d columns", len(row))
	}

	size := 160

	for _, v := range row {
		switch x := v.(type) {
		case string:
			size += len(x)
		case []byte:
			size += len(x)
		}
	}

	if size > contentHashCopyMaxBytes {
		if err := s.flush(ctx, tx); err != nil {
			return err
		}
		return s.copyRows(ctx, tx, [][]any{row})
	}

	if len(s.rows) > 0 &&
		(len(s.rows) >= contentHashCopyMaxRows ||
			s.bytes+size > contentHashCopyMaxBytes) {
		if err := s.flush(ctx, tx); err != nil {
			return err
		}
	}

	s.rows = append(s.rows, row)
	s.bytes += size

	if len(s.rows) >= contentHashCopyMaxRows {
		return s.flush(ctx, tx)
	}

	return nil
}

func (s *contentHashCopyState) copyRows(
	ctx context.Context, tx pgx.Tx, rows [][]any,
) error {
	started := time.Now()

	count, err := tx.CopyFrom(
		ctx,
		pgx.Identifier{"fi", "content_hash_observation"},
		[]string{
			"source_record_id",
			"state",
			"bytes_hashed",
			"md5",
			"sha1",
			"sha256",
			"reason_code",
			"detail",
		},
		pgx.CopyFromRows(rows),
	)

	s.duration += time.Since(started)

	if err != nil {
		return fmt.Errorf("COPY FI content hash observations: %w", err)
	}
	if count != int64(len(rows)) {
		return fmt.Errorf(
			"FI content hash COPY copied %d rows, expected %d",
			count, len(rows),
		)
	}

	s.copied += count
	s.calls++
	return nil
}

func (s *contentHashCopyState) flush(
	ctx context.Context, tx pgx.Tx,
) error {
	if len(s.rows) == 0 {
		return nil
	}

	if err := s.copyRows(ctx, tx, s.rows); err != nil {
		return err
	}

	s.rows = nil
	s.bytes = 0
	return nil
}
