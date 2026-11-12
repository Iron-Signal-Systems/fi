// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
	"context"
	"crypto/sha256"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/jackc/pgx/v5"
)

// Each fixture has the exact source_record input identity fields. Vary the
// original batch ID to cover both fallback IDs and signed-batch provenance.
func sourceRecordCopyFixtures(count int) ([]securityBulkRecord, []fileSourceBulkRecord) {
	security := make([]securityBulkRecord, count)
	files := make([]fileSourceBulkRecord, count)
	for i := range security {
		batchID := int64(0)
		if i%3 != 0 {
			batchID = int64(i/3 + 900)
		}
		digest := sha256.Sum256([]byte(fmt.Sprintf("signed-test-record-%d", i)))
		record := SourceRecord{
			Record: spool.Record{
				Version: SpoolRecordVersion, RecordKind: "WindowsSecurityEvent",
				ScopeID: fmt.Sprintf("scope-%d", i%7),
			},
			RecordBytes: 128 + i%128,
			WrittenAtUTC: time.Date(2026, 11, 9, 11, 0, 0, i, time.UTC),
		}
		security[i] = securityBulkRecord{
			sourceBatchID: batchID, ordinal: int64(i%800 + 1),
			prepared: record, digest: digest[:],
		}
		record.Record.RecordKind = "FileObservation"
		if i%2 == 0 {
			record.Record.RecordKind = "USNObjectObservation"
		}
		files[i] = fileSourceBulkRecord{
			sourceBatchID: batchID, ordinal: int64(i%800 + 1),
			prepared: record, digest: digest[:],
		}
	}
	return security, files
}

// compareSourceRowStreams checks every column and Go value type in row order.
// It copies the current reusable row before Next, because reusing the backing
// array across Next calls is precisely the intended pgx source contract.
func compareSourceRowStreams(t *testing.T, original, reusable pgx.CopyFromSource, count int) {
	t.Helper()
	if _, err := reusable.Values(); err == nil {
		t.Fatal("reusable source accepted Values before Next")
	}
	for i := 0; i < count; i++ {
		if !original.Next() || !reusable.Next() {
			t.Fatalf("source row %d missing", i)
		}
		want, err := original.Values()
		if err != nil {
			t.Fatal(err)
		}
		got, err := reusable.Values()
		if err != nil {
			t.Fatal(err)
		}
		if len(want) != 9 || len(got) != 9 {
			t.Fatalf("row %d not nine columns: legacy=%d reusable=%d", i, len(want), len(got))
		}
		for column := range want {
			if !reflect.DeepEqual(want[column], got[column]) {
				t.Fatalf("row %d column %d mismatch: legacy=%#v (%T) reusable=%#v (%T)",
					i, column, want[column], want[column], got[column], got[column])
			}
		}
		again, err := reusable.Values()
		if err != nil || !reflect.DeepEqual(got, again) {
			t.Fatalf("reusable row %d changed before Next: %v", i, err)
		}
	}
	if original.Next() || reusable.Next() {
		t.Fatal("source returned more rows than expected")
	}
	if _, err := reusable.Values(); err == nil {
		t.Fatal("reusable source accepted Values after exhaustion")
	}
	if err := original.Err(); err != nil {
		t.Fatal(err)
	}
	if err := reusable.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestSourceRecordReusableCOPYSourceMatchesLegacyNineColumns(t *testing.T) {
	security, files := sourceRecordCopyFixtures(19)
	p3, err := withFixedSecurityBulkProfile(context.Background(), "P3")
	if err != nil {
		t.Fatal(err)
	}
	private := WithPrivateSecurityFieldPartitions(p3)
	const fallbackBatchID int64 = 41
	t.Run("security", func(t *testing.T) {
		original := securitySourceRecordCopyRows(context.Background(), security, fallbackBatchID)
		reusable := securitySourceRecordCopyRows(private, security, fallbackBatchID)
		if _, ok := reusable.(*securitySourceRecordCopySource); !ok {
			t.Fatal("private P3 Security source did not select reusable rows")
		}
		compareSourceRowStreams(t, original, reusable, len(security))
	})
	t.Run("file-and-usn", func(t *testing.T) {
		original := fileSourceRecordCopyRows(context.Background(), files, fallbackBatchID)
		reusable := fileSourceRecordCopyRows(private, files, fallbackBatchID)
		if _, ok := reusable.(*fileSourceRecordCopySource); !ok {
			t.Fatal("private P3 File source did not select reusable rows")
		}
		compareSourceRowStreams(t, original, reusable, len(files))
	})
}

func TestSourceRecordReusableCOPYSourcePrivateOnly(t *testing.T) {
	security, files := sourceRecordCopyFixtures(2)
	p3, err := withFixedSecurityBulkProfile(context.Background(), "P3")
	if err != nil {
		t.Fatal(err)
	}
	contexts := []struct {
		name string
		ctx  context.Context
	}{
		{"production-default", context.Background()},
		{"ordinary-p3", p3},
		{"private-default-p1", WithPrivateSecurityFieldPartitions(context.Background())},
	}
	for _, test := range contexts {
		t.Run(test.name, func(t *testing.T) {
			if _, ok := securitySourceRecordCopyRows(test.ctx, security, 41).(*securitySourceRecordCopySource); ok {
				t.Fatal("nonprivate-P3 Security source unexpectedly selected reusable rows")
			}
			if _, ok := fileSourceRecordCopyRows(test.ctx, files, 41).(*fileSourceRecordCopySource); ok {
				t.Fatal("nonprivate-P3 File source unexpectedly selected reusable rows")
			}
		})
	}
}

func TestSourceRecordReusableCOPYSourceEmpty(t *testing.T) {
	security := newSecuritySourceRecordCopySource(nil, 41)
	if security.Next() {
		t.Fatal("empty Security source returned a row")
	}
	if _, err := security.Values(); err == nil {
		t.Fatal("empty Security source accepted Values")
	}
	files := newFileSourceRecordCopySource(nil, 41)
	if files.Next() {
		t.Fatal("empty File source returned a row")
	}
	if _, err := files.Values(); err == nil {
		t.Fatal("empty File source accepted Values")
	}
}

var sourceRecordCopyBenchmarkSink int64

func benchmarkSourceRecordCopyRows(b *testing.B, newSource func() pgx.CopyFromSource) {
	b.Helper()
	b.ReportAllocs()
	var result int64
	for n := 0; n < b.N; n++ {
		rows := newSource()
		for rows.Next() {
			values, err := rows.Values()
			if err != nil {
				b.Fatal(err)
			}
			result += values[1].(int64) + int64(len(values[7].([]byte)))
		}
		if err := rows.Err(); err != nil {
			b.Fatal(err)
		}
	}
	sourceRecordCopyBenchmarkSink = result
}

func BenchmarkSecuritySourceRecordCOPYLegacyVsReusable(b *testing.B) {
	security, _ := sourceRecordCopyFixtures(4096)
	p3, err := withFixedSecurityBulkProfile(context.Background(), "P3")
	if err != nil {
		b.Fatal(err)
	}
	private := WithPrivateSecurityFieldPartitions(p3)
	b.Run("legacy-slice", func(b *testing.B) {
		benchmarkSourceRecordCopyRows(b, func() pgx.CopyFromSource {
			return securitySourceRecordCopyRows(context.Background(), security, 41)
		})
	})
	b.Run("reusable-source", func(b *testing.B) {
		benchmarkSourceRecordCopyRows(b, func() pgx.CopyFromSource {
			return securitySourceRecordCopyRows(private, security, 41)
		})
	})
}

func BenchmarkFileSourceRecordCOPYLegacyVsReusable(b *testing.B) {
	_, files := sourceRecordCopyFixtures(4096)
	p3, err := withFixedSecurityBulkProfile(context.Background(), "P3")
	if err != nil {
		b.Fatal(err)
	}
	private := WithPrivateSecurityFieldPartitions(p3)
	b.Run("legacy-slice", func(b *testing.B) {
		benchmarkSourceRecordCopyRows(b, func() pgx.CopyFromSource {
			return fileSourceRecordCopyRows(context.Background(), files, 41)
		})
	})
	b.Run("reusable-source", func(b *testing.B) {
		benchmarkSourceRecordCopyRows(b, func() pgx.CopyFromSource {
			return fileSourceRecordCopyRows(private, files, 41)
		})
	})
}
