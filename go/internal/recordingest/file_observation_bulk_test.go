// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/jackc/pgx/v5"
)

type noSQLFileObservationBulkTx struct{ pgx.Tx }

func TestFileObservationBulkInputBounds(t *testing.T) {
	state := newFileObservationBulkState()
	if err := state.add(context.Background(), noSQLFileObservationBulkTx{}, fileObservationBulkRecord{}); err == nil {
		t.Fatal("accepted incomplete file projection identity")
	}
	if len(state.records) != 0 {
		t.Fatal("invalid record was queued")
	}
	item := fileObservationBulkRecord{sourceID: "source-A", sourceRecordID: 99, ordinal: 2, bytes: 128}
	if err := state.add(context.Background(), noSQLFileObservationBulkTx{}, item); err != nil {
		t.Fatal(err)
	}
	if len(state.records) != 1 || state.bytes != 128 {
		t.Fatal("file observation queue mismatch")
	}
	if err := state.add(context.Background(), noSQLFileObservationBulkTx{}, fileObservationBulkRecord{sourceID: "", sourceRecordID: 100, bytes: 1}); err == nil {
		t.Fatal("accepted missing source identity")
	}
}

func TestFileBulkNumeric(t *testing.T) {
	for _, value := range []string{"0", "18446744073709551615", "99999999999999999999"} {
		n, err := fileBulkNumeric(value)
		if err != nil || n.Int.String() != value {
			t.Fatalf("numeric %q: %v %#v", value, err, n)
		}
	}
	for _, value := range []string{"", "-1", "1.1", "abc"} {
		if _, err := fileBulkNumeric(value); err == nil {
			t.Fatalf("accepted invalid numeric %q", value)
		}
	}
}

func TestFileValidationSourceRejectsMalformedAndDirectDoesNotBypass(t *testing.T) {
	checked, err := validateSourceFileObservation(ntfs.Observation{})
	if err == nil || checked != nil {
		t.Fatal("malformed observation received a validated source value")
	}
	direct := fileObservationBulkRecord{
		sourceID: "source-A", sourceRecordID: 7, bytes: 80,
		value: ntfs.Observation{},
	}
	if direct.validatedSource != nil {
		t.Fatal("direct record may not bypass validation")
	}
	_, _, err = prepareFileObservationBulk(context.Background(), noSQLFileObservationBulkTx{}, direct)
	if err == nil {
		t.Fatal("invalid direct bulk input reached SQL without validation")
	}
}

func TestFileBulkConstructorBindsOriginalAndValidatedValue(t *testing.T) {
	checked := &validatedSourceFileObservation{
		observation: ntfs.Observation{ObservedAt: "2026-11-08T00:00:00.000000000Z"},
	}
	record, err := fileBulkRecordFromValidatedSource("source-A", 11, 2, checked, nil, 100)
	if err != nil || record.validatedSource != checked ||
		record.value.ObservedAt != checked.observation.ObservedAt {
		t.Fatalf("validated constructor did not populate all bulk readers: %#v err=%v", record, err)
	}
	if _, err = fileBulkRecordFromValidatedSource("source-A", 11, 2, nil, nil, 100); err == nil {
		t.Fatal("bulk constructor accepted nil source validation proof")
	}
	direct := fileObservationBulkRecord{value: ntfs.Observation{ObservedAt: "direct"}}
	if direct.value.ObservedAt != "direct" || direct.validatedSource != nil {
		t.Fatal("legacy/direct bulk value changed or bypasses validation")
	}
}
