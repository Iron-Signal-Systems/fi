// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	usnCopyChangeLimit = 1024
	usnCopyReasonLimit = 2048
	usnCopyByteLimit   = 2 << 20
)

type usnChangeCopyContextKey struct{}

type usnCopyBuffer struct {
	rows  [][]any
	bytes int
}

type usnChangeCopyState struct {
	changes usnCopyBuffer
	reasons usnCopyBuffer

	changeRows  int64
	reasonRows  int64
	changeCalls int64
	reasonCalls int64
	duration    time.Duration
}

func newUSNChangeCopyState() *usnChangeCopyState {
	return &usnChangeCopyState{}
}

func (state *usnChangeCopyState) add(
	ctx context.Context,
	tx pgx.Tx,
	row []any,
	reasonNames []string,
) error {
	if len(row) != 13 {
		return fmt.Errorf("FI USN COPY expected 13 change columns")
	}

	usn, ok := row[4].(string)
	if !ok {
		return fmt.Errorf("FI USN COPY numeric source type invalid")
	}

	number, ok := new(big.Int).SetString(usn, 10)
	if !ok {
		return fmt.Errorf("FI USN COPY numeric value invalid")
	}

	filename, ok := row[10].([]byte)
	if !ok {
		return fmt.Errorf("FI USN COPY filename type invalid")
	}

	size := 192 + len(usn) + len(filename)
	if size > usnCopyByteLimit {
		return fmt.Errorf("FI USN COPY change exceeds byte limit")
	}

	if len(state.changes.rows) > 0 &&
		(len(state.changes.rows) >= usnCopyChangeLimit ||
			state.changes.bytes+size > usnCopyByteLimit) {
		if err := state.flushAll(ctx, tx); err != nil {
			return err
		}
	}

	prepared := append([]any(nil), row...)
	prepared[4] = pgtype.Numeric{
		Int:   number,
		Exp:   0,
		Valid: true,
	}

	state.changes.rows = append(state.changes.rows, prepared)
	state.changes.bytes += size

	for i, reason := range reasonNames {
		reasonSize := 64 + len(reason)
		if reasonSize > usnCopyByteLimit {
			return fmt.Errorf("FI USN COPY reason exceeds byte limit")
		}

		if len(state.reasons.rows) > 0 &&
			(len(state.reasons.rows) >= usnCopyReasonLimit ||
				state.reasons.bytes+reasonSize > usnCopyByteLimit) {
			if err := state.flushAll(ctx, tx); err != nil {
				return err
			}
		}

		state.reasons.rows = append(state.reasons.rows, []any{
			row[0], row[1], i + 1, reason,
		})
		state.reasons.bytes += reasonSize
	}

	if len(state.changes.rows) >= usnCopyChangeLimit ||
		len(state.reasons.rows) >= usnCopyReasonLimit {
		return state.flushAll(ctx, tx)
	}

	return nil
}

func (state *usnChangeCopyState) flushAll(
	ctx context.Context,
	tx pgx.Tx,
) error {
	if err := state.flushChanges(ctx, tx); err != nil {
		return err
	}
	return state.flushReasons(ctx, tx)
}

func (state *usnChangeCopyState) flushChanges(
	ctx context.Context,
	tx pgx.Tx,
) error {
	if len(state.changes.rows) == 0 {
		return nil
	}

	columns := []string{
		"source_record_id",
		"change_ordinal",
		"major_version",
		"minor_version",
		"usn",
		"event_timestamp",
		"reason_raw",
		"source_info_raw",
		"security_id",
		"file_attributes_raw",
		"file_name_utf16le",
		"file_ntfs_object_id",
		"parent_ntfs_object_id",
	}

	expected := int64(len(state.changes.rows))
	started := time.Now()

	count, err := tx.CopyFrom(
		ctx,
		pgx.Identifier{"fi", "usn_object_change"},
		columns,
		pgx.CopyFromRows(state.changes.rows),
	)

	state.duration += time.Since(started)

	if err != nil {
		return fmt.Errorf("FI USN change COPY: %w", err)
	}
	if count != expected {
		return fmt.Errorf(
			"FI USN change COPY wrote %d, expected %d",
			count, expected,
		)
	}

	state.changeRows += count
	state.changeCalls++
	state.changes.rows = nil
	state.changes.bytes = 0

	return nil
}

func (state *usnChangeCopyState) flushReasons(
	ctx context.Context,
	tx pgx.Tx,
) error {
	if len(state.reasons.rows) == 0 {
		return nil
	}

	expected := int64(len(state.reasons.rows))
	started := time.Now()

	count, err := tx.CopyFrom(
		ctx,
		pgx.Identifier{"fi", "usn_object_change_reason"},
		[]string{
			"source_record_id",
			"change_ordinal",
			"reason_ordinal",
			"reason_name",
		},
		pgx.CopyFromRows(state.reasons.rows),
	)

	state.duration += time.Since(started)

	if err != nil {
		return fmt.Errorf("FI USN reason COPY: %w", err)
	}
	if count != expected {
		return fmt.Errorf(
			"FI USN reason COPY wrote %d, expected %d",
			count, expected,
		)
	}

	state.reasonRows += count
	state.reasonCalls++
	state.reasons.rows = nil
	state.reasons.bytes = 0

	return nil
}
