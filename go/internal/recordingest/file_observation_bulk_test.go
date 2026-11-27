// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"github.com/jackc/pgx/v5"
	"testing"
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
