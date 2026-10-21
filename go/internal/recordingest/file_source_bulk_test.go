// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"bytes"
	"context"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/jackc/pgx/v5"
)

type noSQLFileSourceBulkTx struct{ pgx.Tx }

func TestFileSourceBulkRejectsInvalidRecords(t *testing.T) {
	record := func(ordinal int64) fileSourceBulkRecord {
		return fileSourceBulkRecord{ordinal: ordinal, digest: bytes.Repeat([]byte{7}, 32),
			prepared: SourceRecord{Record: spool.Record{RecordKind: "FileObservation"}, RecordBytes: 17}}
	}
	tests := []struct {
		name    string
		pending []fileSourceBulkRecord
	}{
		{name: "zero ordinal", pending: []fileSourceBulkRecord{record(0)}},
		{name: "ordinal gap", pending: []fileSourceBulkRecord{record(3), record(5)}},
		{name: "duplicate ordinal", pending: []fileSourceBulkRecord{record(3), record(3)}},
		{name: "wrong kind", pending: func() []fileSourceBulkRecord {
			p := record(3)
			p.prepared.Record.RecordKind = "WindowsSecurityEvent"
			return []fileSourceBulkRecord{p}
		}()},
		{name: "wrong digest", pending: func() []fileSourceBulkRecord { p := record(3); p.digest = []byte{3}; return []fileSourceBulkRecord{p} }()},
		{name: "zero bytes", pending: func() []fileSourceBulkRecord {
			p := record(3)
			p.prepared.RecordBytes = 0
			return []fileSourceBulkRecord{p}
		}()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := copyFileSourceBulk(context.Background(), noSQLFileSourceBulkTx{}, 41, tc.pending, &ingestStageProfile{})
			if err == nil {
				t.Fatal("invalid FileObservation COPY input accepted")
			}
		})
	}
	oversize := make([]fileSourceBulkRecord, fileSourceBulkMaxRecords+1)
	for i := range oversize {
		oversize[i] = record(int64(i + 1))
	}
	if err := copyFileSourceBulk(context.Background(), noSQLFileSourceBulkTx{}, 41, oversize, &ingestStageProfile{}); err == nil {
		t.Fatal("chunk larger than the record limit was accepted")
	}
}
