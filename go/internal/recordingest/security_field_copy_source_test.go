// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestSecurityFieldCopyCursorPreservesOrderAndOrdinals(t *testing.T) {
	pending := []securityBulkRecord{
		{sourceRecordID: 101, value: records.WindowsSecurityEventObservation{Fields: []records.WindowsSecurityEventField{{Name: "A", Value: "one"}, {Name: "B", Value: "two"}}}},
		{sourceRecordID: 102}, // zero fields must not create a phantom row
		{sourceRecordID: 103, value: records.WindowsSecurityEventObservation{Fields: []records.WindowsSecurityEventField{{Name: "C", Value: "three"}, {Name: "D", Value: "four"}, {Name: "E", Value: "five"}}}},
	}
	cursor := newSecurityFieldCopyCursor(pending)
	var got [][]any
	var sizes []int
	for cursor.hasNext() {
		chunk := securityFieldCopyChunk{cursor: cursor, maxRows: 2, maxBytes: 1 << 20}
		for chunk.Next() {
			values, err := chunk.Values()
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, append([]any(nil), values...))
		}
		if chunk.Err() != nil {
			t.Fatal(chunk.Err())
		}
		if chunk.rows == 0 {
			t.Fatal("zero-row COPY chunk")
		}
		sizes = append(sizes, chunk.rows)
	}
	want := [][]any{
		{int64(101), 1, "A", "one"},
		{int64(101), 2, "B", "two"},
		{int64(103), 1, "C", "three"},
		{int64(103), 2, "D", "four"},
		{int64(103), 3, "E", "five"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ordered fields mismatch: got %v want %v", got, want)
	}
	if !reflect.DeepEqual(sizes, []int{2, 2, 1}) {
		t.Fatalf("chunk sizes: %v", sizes)
	}
}

func TestSecurityFieldCopyCursorByteBudgetAndOversize(t *testing.T) {
	pending := []securityBulkRecord{{sourceRecordID: 7, value: records.WindowsSecurityEventObservation{Fields: []records.WindowsSecurityEventField{
		{Name: "A", Value: "x"},
		{Name: "B", Value: strings.Repeat("z", 200)},
		{Name: "C", Value: "y"},
	}}}}
	cursor := newSecurityFieldCopyCursor(pending)
	var rows, oversized int
	var chunkSizes []int
	for cursor.hasNext() {
		chunk := securityFieldCopyChunk{cursor: cursor, maxRows: 16, maxBytes: 80}
		for chunk.Next() {
			rows++
		}
		if chunk.oversized {
			oversized++
		}
		if chunk.rows == 0 {
			t.Fatal("no forward progress")
		}
		chunkSizes = append(chunkSizes, chunk.rows)
	}
	if rows != 3 || oversized != 1 || !reflect.DeepEqual(chunkSizes, []int{1, 1, 1}) {
		t.Fatalf("rows=%d oversized=%d chunks=%v", rows, oversized, chunkSizes)
	}
}

func TestSecurityFieldCopyCursorEmpty(t *testing.T) {
	cursor := newSecurityFieldCopyCursor([]securityBulkRecord{{sourceRecordID: 1}})
	if cursor.hasNext() {
		t.Fatal("empty event generated a field")
	}
}
