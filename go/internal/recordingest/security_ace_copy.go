// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"fmt"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	aceCopyMaxRecords = 1024
	aceCopyMaxBytes   = 2 << 20
)

type aceCopyContextKey struct{}

type aceCopyBuffer struct {
	rows  [][]any
	bytes int
}

type aceCopyState struct {
	dacl aceCopyBuffer
	sacl aceCopyBuffer

	daclRows int64
	saclRows int64
	calls    int64
	duration time.Duration
}

func newACECopyState() *aceCopyState {
	return &aceCopyState{}
}

func parseACECopyUUID(value string) (any, error) {
	if value == "" {
		return nil, nil
	}

	var parsed pgtype.UUID
	if err := parsed.Scan(value); err != nil {
		return nil, fmt.Errorf("parse FI ACE UUID: %w", err)
	}

	return parsed, nil
}

func prepareACECopyRow(
	sourceRecordID int64,
	value records.ACEObservation,
) ([]any, int, error) {
	ordinal, err := parseUint(value.Index, 32, "ace.index")
	if err != nil {
		return nil, 0, err
	}
	aceType, err := parseUint(value.Type, 8, "ace.type")
	if err != nil {
		return nil, 0, err
	}
	flags, err := parseUint(value.Flags, 8, "ace.flags")
	if err != nil {
		return nil, 0, err
	}
	size, err := parseUint(value.Size, 16, "ace.size")
	if err != nil {
		return nil, 0, err
	}
	raw, err := decodeBase64URL(value.RawBase64URL, true, "ace.raw")
	if err != nil {
		return nil, 0, err
	}
	mask, err := optionalUintValue(value.Mask, 32, "ace.mask")
	if err != nil {
		return nil, 0, err
	}
	objectFlags, err := optionalUintValue(value.ObjectFlags, 32, "ace.object_flags")
	if err != nil {
		return nil, 0, err
	}
	objectGUID, err := parseACECopyUUID(value.ObjectTypeGUID)
	if err != nil {
		return nil, 0, err
	}
	inheritedGUID, err := parseACECopyUUID(value.InheritedObjectTypeGUID)
	if err != nil {
		return nil, 0, err
	}

	row := []any{
		sourceRecordID,
		int(ordinal),
		int(aceType),
		value.TypeName,
		int(flags),
		int(size),
		raw,
		mask,
		objectFlags,
		objectGUID,
		inheritedGUID,
		nullString(value.SID),
	}

	bytes := 192 + len(raw) + len(value.TypeName) +
		len(value.ObjectTypeGUID) +
		len(value.InheritedObjectTypeGUID) +
		len(value.SID)

	return row, bytes, nil
}

func (state *aceCopyState) add(
	ctx context.Context,
	tx pgx.Tx,
	table string,
	sourceRecordID int64,
	ace records.ACEObservation,
) error {
	var buffer *aceCopyBuffer

	switch table {
	case "fi.security_ace":
		buffer = &state.dacl
	case "fi.sacl_ace":
		buffer = &state.sacl
	default:
		return fmt.Errorf("unsupported FI ACE COPY table %q", table)
	}

	row, bytes, err := prepareACECopyRow(sourceRecordID, ace)
	if err != nil {
		return err
	}

	if bytes > aceCopyMaxBytes {
		return fmt.Errorf("FI ACE COPY row exceeds byte limit")
	}

	if len(buffer.rows) > 0 &&
		(len(buffer.rows) >= aceCopyMaxRecords ||
			buffer.bytes+bytes > aceCopyMaxBytes) {
		if err := state.flush(ctx, tx, table); err != nil {
			return err
		}
	}

	buffer.rows = append(buffer.rows, row)
	buffer.bytes += bytes

	if len(buffer.rows) >= aceCopyMaxRecords {
		return state.flush(ctx, tx, table)
	}

	return nil
}

func (state *aceCopyState) flush(
	ctx context.Context,
	tx pgx.Tx,
	table string,
) error {
	var buffer *aceCopyBuffer
	var identifier pgx.Identifier

	switch table {
	case "fi.security_ace":
		buffer = &state.dacl
		identifier = pgx.Identifier{"fi", "security_ace"}
	case "fi.sacl_ace":
		buffer = &state.sacl
		identifier = pgx.Identifier{"fi", "sacl_ace"}
	default:
		return fmt.Errorf("unsupported FI ACE COPY table %q", table)
	}

	if len(buffer.rows) == 0 {
		return nil
	}

	columns := []string{
		"source_record_id",
		"ace_ordinal",
		"ace_type",
		"type_name",
		"flags",
		"ace_size",
		"raw_ace",
		"access_mask",
		"object_flags",
		"object_type_guid",
		"inherited_object_type_guid",
		"sid",
	}

	expected := int64(len(buffer.rows))
	started := time.Now()

	copied, err := tx.CopyFrom(
		ctx,
		identifier,
		columns,
		pgx.CopyFromRows(buffer.rows),
	)

	state.duration += time.Since(started)

	if err != nil {
		return fmt.Errorf("FI ACE COPY %s: %w", table, err)
	}
	if copied != expected {
		return fmt.Errorf(
			"FI ACE COPY %s wrote %d rows, expected %d",
			table, copied, expected,
		)
	}

	switch table {
	case "fi.security_ace":
		state.daclRows += copied
	case "fi.sacl_ace":
		state.saclRows += copied
	}

	state.calls++
	buffer.rows = nil
	buffer.bytes = 0

	return nil
}

func (state *aceCopyState) flushAll(
	ctx context.Context,
	tx pgx.Tx,
) error {
	if err := state.flush(ctx, tx, "fi.security_ace"); err != nil {
		return err
	}
	return state.flush(ctx, tx, "fi.sacl_ace")
}
