// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Acceptance for the ACTIVE bounded Security SQL COPY row adapters.
// These compare original 9-column source and 4-column scope data, types,
// order, and IDs rather than asserting only that dormant helpers compile.
package recordingest

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/jackc/pgx/v5"
)

var (
	_ pgx.CopyFromSource = (*securitySourceCopySource)(nil)
	_ pgx.CopyFromSource = (*securityEventCopySource)(nil)
	_ pgx.CopyFromSource = (*securityScopeCopySource)(nil)
	_ pgx.CopyFromSource = (*securityFieldCopyChunk)(nil)
)

func TestSecuritySourceReusableCopyMatchesLegacyNineColumns(t *testing.T) {
	pending := candidateSecurityEventFixture(5)
	for i := range pending {
		p := &pending[i]
		p.ordinal = int64(i + 11)
		p.sourceBatchID = 0
		if i >= 2 {
			p.sourceBatchID = 48
		}
		p.prepared.Record = spool.Record{
			Version: SpoolRecordVersion, RecordKind: "WindowsSecurityEvent",
			ScopeID: "finance", WrittenAt: "2026-11-12T01:01:01Z",
		}
		p.prepared.WrittenAtUTC = time.Date(2026, 11, 12, 1, 1, 1, 0, time.UTC)
		p.prepared.RecordBytes = 791 + i
		p.digest = bytes.Repeat([]byte{byte(i + 1)}, 32)
	}
	source := newSecuritySourceCopySource(pending, 41)
	if _, err := source.Values(); err == nil {
		t.Fatal("source returned Values before Next")
	}
	for i := range pending {
		if !source.Next() {
			t.Fatalf("source skipped row %d", i)
		}
		got, err := source.Values()
		if err != nil {
			t.Fatal(err)
		}
		p := pending[i]
		want := []any{
			bulkSourceBatchID(p.sourceBatchID, 41), p.ordinal,
			p.prepared.Record.Version, p.prepared.Record.RecordKind,
			p.prepared.Record.ScopeID, p.prepared.WrittenAtUTC,
			p.prepared.RecordBytes, p.digest, IngestVersion,
		}
		if len(got) != 9 || !reflect.DeepEqual(got, want) {
			t.Fatalf("source row %d changed SQL COPY column value/type/order", i)
		}
	}
	if source.Next() {
		t.Fatal("source emitted extra row")
	}
	if source.Err() != nil {
		t.Fatal(source.Err())
	}
	if source.Next() {
		t.Fatal("source restarted after EOF")
	}
	if empty := newSecuritySourceCopySource(nil, 41); empty.Next() {
		t.Fatal("empty source emitted a row")
	}
}

func TestSecurityScopeReusableCopyMatchesLegacyFourColumns(t *testing.T) {
	pending := candidateSecurityEventFixture(5)
	pending[0].value.MatchedScopes = []records.WindowsSecurityMatchedScope{
		{ScopeID: "finance", GovernedRoot: `D:\Finance`},
		{ScopeID: "public", GovernedRoot: `D:\Public`},
	}
	pending[1].value.MatchedScopes = nil
	pending[2].value.MatchedScopes = []records.WindowsSecurityMatchedScope{
		{ScopeID: "archive", GovernedRoot: `E:\Archive`},
	}
	pending[3].value.MatchedScopes = []records.WindowsSecurityMatchedScope{}
	pending[4].value.MatchedScopes = []records.WindowsSecurityMatchedScope{
		{ScopeID: "audit", GovernedRoot: `C:\Audit`},
	}
	want := make([][]any, 0, 4)
	for _, p := range pending {
		for i, scope := range p.value.MatchedScopes {
			want = append(want, []any{p.sourceRecordID, i + 1, scope.ScopeID, scope.GovernedRoot})
		}
	}
	cursor := newSecurityScopeCopySource(pending)
	if _, err := cursor.Values(); err == nil {
		t.Fatal("scope returned Values before Next")
	}
	var got [][]any
	for cursor.Next() {
		values, err := cursor.Values()
		if err != nil {
			t.Fatal(err)
		}
		if len(values) != 4 {
			t.Fatalf("scope COPY emitted %d instead of four columns", len(values))
		}
		// Copy because the source deliberately reuses its row storage.
		got = append(got, append([]any(nil), values...))
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scope COPY changed parent IDs, ordinals or row order: got=%v want=%v", got, want)
	}
	if _, err := cursor.Values(); err == nil {
		t.Fatal("scope returned Values after EOF")
	}
	if cursor.Err() != nil {
		t.Fatal(cursor.Err())
	}
	if cursor.Next() {
		t.Fatal("scope cursor restarted after EOF")
	}
	if empty := newSecurityScopeCopySource(nil); empty.Next() {
		t.Fatal("empty scope source emitted a row")
	}
}

func BenchmarkSecuritySourceReusableCopyRows(b *testing.B) {
	pending := candidateSecurityEventFixture(4096)
	for i := range pending {
		pending[i].ordinal = int64(i + 1)
		pending[i].prepared.Record.Version = SpoolRecordVersion
		pending[i].prepared.Record.RecordKind = "WindowsSecurityEvent"
		pending[i].digest = bytes.Repeat([]byte{0x55}, 32)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rows := newSecuritySourceCopySource(pending, 41)
		for rows.Next() {
			if _, err := rows.Values(); err != nil {
				b.Fatal(err)
			}
		}
		if err := rows.Err(); err != nil {
			b.Fatal(err)
		}
	}
}
