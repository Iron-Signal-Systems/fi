// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Windows Security event-field COPY input. This file deliberately contains no
// PostgreSQL transaction lifecycle logic: the caller owns atomicity and rollback.
package recordingest

// The child-field COPY budget is independent of the parent event and source
// byte budgets. It bounds how many rows a COPY call consumes while preventing
// a second, giant [][]any allocation for decoded child fields.
//
// These are v1 conservative values, not yet adaptive tuning parameters.
const (
	securityFieldCopyMaxRows  = 16_384
	securityFieldCopyMaxBytes = 4 << 20
	securityFieldRowOverhead  = 48 // conservative row/framing allowance in budget, not an on-wire measurement
)

// securityFieldCopyCursor owns the position in the already-validated parent
// observations. It never duplicates or reorders source field values.
//
// Each chunk uses exactly this cursor and stops before a row that would exceed
// either configured budget. A single over-budget row is accepted alone because
// source validation already admitted it and a COPY boundary must not discard
// evidence. That exceptional row must be counted by telemetry at the caller.
type securityFieldCopyCursor struct {
	pending    []securityBulkRecord
	eventIndex int
	fieldIndex int
}

func newSecurityFieldCopyCursor(pending []securityBulkRecord) *securityFieldCopyCursor {
	return &securityFieldCopyCursor{pending: pending}
}

// hasNext skips events with no fields. Skipping an empty event does not affect
// the ordinal of any field belonging to a later event.
func (c *securityFieldCopyCursor) hasNext() bool {
	for c.eventIndex < len(c.pending) {
		if c.fieldIndex < len(c.pending[c.eventIndex].value.Fields) {
			return true
		}
		c.eventIndex++
		c.fieldIndex = 0
	}
	return false
}

// securityFieldCopyChunk satisfies the pgx.CopyFromSource interface. Values
// reuses a four-element array; the caller must consume its returned values
// before calling Next again, as pgx.CopyFrom does.
//
// Bytes are approximate buffered *input* bytes, not PostgreSQL disk or WAL
// bytes. The bound is based on UTF-8 field value lengths plus framing allowance.
type securityFieldCopyChunk struct {
	cursor    *securityFieldCopyCursor
	maxRows   int
	maxBytes  int64
	rows      int
	bytes     int64
	oversized bool
	values    [4]any
}

func (c *securityFieldCopyChunk) Next() bool {
	if c.rows >= c.maxRows || !c.cursor.hasNext() {
		return false
	}
	parent := &c.cursor.pending[c.cursor.eventIndex]
	field := &parent.value.Fields[c.cursor.fieldIndex]
	rowBytes := int64(len(field.Name)) + int64(len(field.Value)) + securityFieldRowOverhead
	if c.rows > 0 && c.bytes+rowBytes > c.maxBytes {
		return false
	}
	if c.rows == 0 && rowBytes > c.maxBytes {
		// One oversized source field may exceed the nominal COPY byte limit;
		// it is isolated in its own COPY and never silently skipped.
		c.oversized = true
	}
	c.values[0] = parent.sourceRecordID
	c.values[1] = c.cursor.fieldIndex + 1
	c.values[2] = field.Name
	c.values[3] = field.Value
	c.rows++
	c.bytes += rowBytes
	c.cursor.fieldIndex++
	return true
}

func (c *securityFieldCopyChunk) Values() ([]any, error) {
	return c.values[:], nil
}

func (c *securityFieldCopyChunk) Err() error { return nil }
