// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"reflect"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestPrivateP3FieldCOPYExperimentCannotChangeDefaultOrOrdinaryP3(t *testing.T) {
	base := context.Background()
	p3, err := withFixedSecurityBulkProfile(base, "P3")
	if err != nil {
		t.Fatal(err)
	}
	p1, err := withFixedSecurityBulkProfile(base, "P1")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		ctx  context.Context
		rows int
		bytes int64
	}{
		{"nil", nil, securityFieldCopyMaxRows, securityFieldCopyMaxBytes},
		{"default", base, securityFieldCopyMaxRows, securityFieldCopyMaxBytes},
		{"ordinary-P3", p3, standardP3FieldCopyMaxRows, standardP3FieldCopyMaxBytes},
		{"private-P1", WithPrivateSecurityFieldPartitions(p1), securityFieldCopyMaxRows, securityFieldCopyMaxBytes},
		{"private-P3", WithPrivateSecurityFieldPartitions(p3), privateP3FieldCopyMaxRows, privateP3FieldCopyMaxBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := securityFieldCopyRowsForContext(tc.ctx); got != tc.rows {
				t.Fatalf("rows=%d, want=%d", got, tc.rows)
			}
			if got := securityFieldCopyBytesForContext(tc.ctx); got != tc.bytes {
				t.Fatalf("bytes=%d, want=%d", got, tc.bytes)
			}
		})
	}
}

func TestPrivateP3FieldCOPYLargerChunksKeepAllOrdinals(t *testing.T) {
	// A realistic four-thousand-or-fewer-event Security flush containing
	// 65,539 validated field rows. COPY must preserve every original ordinal
	// across either size of chunk; no source/event grouping may change.
	pending := make([]securityBulkRecord, 2049)
	for i := range pending {
		n := 32
		if i == len(pending)-1 {
			n = 3
		}
		fields := make([]records.WindowsSecurityEventField, n)
		for j := range fields {
			fields[j] = records.WindowsSecurityEventField{Name: "Field", Value: "value"}
		}
		pending[i] = securityBulkRecord{
			sourceRecordID: int64(i + 101),
			value: records.WindowsSecurityEventObservation{Fields: fields},
		}
	}

	for _, tc := range []struct {
		name string
		maxRows int
		maxBytes int64
		chunkRows []int
	}{
		{"ordinary-P3", standardP3FieldCopyMaxRows, standardP3FieldCopyMaxBytes, []int{32768, 32768, 3}},
		{"private-P3", privateP3FieldCopyMaxRows, privateP3FieldCopyMaxBytes, []int{65536, 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cursor := newSecurityFieldCopyCursor(pending)
			var chunks []int
			total := 0
			for cursor.hasNext() {
				chunk := securityFieldCopyChunk{cursor: cursor, maxRows: tc.maxRows, maxBytes: tc.maxBytes}
				for chunk.Next() {
					vals, err := chunk.Values()
					if err != nil {
						t.Fatal(err)
					}
					eventID := cursor.eventIndex
					// Next already moved fieldIndex; it may still point into
					// the same event until hasNext advances to the next.
					if eventID >= len(pending) || vals[0] != pending[eventID].sourceRecordID ||
						vals[1] != cursor.fieldIndex || vals[2] != "Field" || vals[3] != "value" {
						t.Fatalf("field row/order changed at row %d: %v", total, vals)
					}
					total++
				}
				if chunk.Err() != nil || chunk.rows == 0 || chunk.rows > tc.maxRows || chunk.bytes > tc.maxBytes || chunk.oversized {
					t.Fatalf("invalid bounded chunk: rows=%d bytes=%d", chunk.rows, chunk.bytes)
				}
				chunks = append(chunks, chunk.rows)
			}
			if total != 65539 || !reflect.DeepEqual(chunks, tc.chunkRows) {
				t.Fatalf("field total/chunks changed: rows=%d chunks=%v, want=%v", total, chunks, tc.chunkRows)
			}
		})
	}
}
