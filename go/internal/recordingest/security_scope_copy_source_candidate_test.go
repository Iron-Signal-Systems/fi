// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
)

// legacySecurityScopeValues reproduces the established materialized COPY
// input. It is a regression oracle, not an alternative production writer.
func legacySecurityScopeValues(pending []securityBulkRecord) [][]any {
	var count int
	for _, p := range pending {
		count += len(p.value.MatchedScopes)
	}
	rows := make([][]any, 0, count)
	for _, p := range pending {
		for i, scope := range p.value.MatchedScopes {
			rows = append(rows, []any{p.sourceRecordID, i + 1, scope.ScopeID, scope.GovernedRoot})
		}
	}
	return rows
}

func securityScopeCandidateFixture() []securityBulkRecord {
	return []securityBulkRecord{
		{sourceRecordID: 101, value: records.WindowsSecurityEventObservation{MatchedScopes: []records.WindowsSecurityMatchedScope{
			{ScopeID: "alpha", GovernedRoot: `C:\Gov Root`},
			{ScopeID: "beta", GovernedRoot: `D:\\fichier\é`},
		}}},
		{sourceRecordID: 102},
		{sourceRecordID: 103, value: records.WindowsSecurityEventObservation{MatchedScopes: []records.WindowsSecurityMatchedScope{
			{ScopeID: "third", GovernedRoot: `E:\share`},
		}}},
		{sourceRecordID: 104, value: records.WindowsSecurityEventObservation{MatchedScopes: []records.WindowsSecurityMatchedScope{}}},
	}
}

func TestSecurityScopeReusableCOPYSourceMatchesLegacy(t *testing.T) {
	pending := securityScopeCandidateFixture()
	want := legacySecurityScopeValues(pending)
	source := newSecurityScopeCopySource(pending)

	if _, err := source.Values(); err == nil {
		t.Fatal("Values before Next unexpectedly succeeded")
	}
	i := 0
	for source.Next() {
		got, err := source.Values()
		if err != nil {
			t.Fatal(err)
		}
		if i >= len(want) {
			t.Fatal("reusable scope source returned unexpected extra row")
		}
		if !reflect.DeepEqual(got, want[i]) {
			t.Fatalf("scope row %d mismatch: got=%#v want=%#v", i, got, want[i])
		}
		// Verify Values is stable until another Next, as pgx requires.
		again, err := source.Values()
		if err != nil || !reflect.DeepEqual(got, again) {
			t.Fatalf("scope row %d was not stable before Next: %v", i, err)
		}
		i++
	}
	if i != len(want) {
		t.Fatalf("reusable scopes=%d legacy=%d", i, len(want))
	}
	if _, err := source.Values(); err == nil {
		t.Fatal("Values after exhaustion unexpectedly succeeded")
	}
	if err := source.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityScopeReusableCOPYSourceEmpty(t *testing.T) {
	for _, pending := range [][]securityBulkRecord{
		nil,
		{},
		{{sourceRecordID: 1}},
		{{sourceRecordID: 1}, {sourceRecordID: 2}},
	} {
		source := newSecurityScopeCopySource(pending)
		if source.Next() {
			t.Fatal("no scopes, but reusable source produced a row")
		}
		if _, err := source.Values(); err == nil {
			t.Fatal("Values after empty Next unexpectedly succeeded")
		}
	}
}

func scopeCopyBenchmarkFixture(count int) []securityBulkRecord {
	pending := make([]securityBulkRecord, count)
	for i := range pending {
		scopes := make([]records.WindowsSecurityMatchedScope, i%5)
		for j := range scopes {
			scopes[j] = records.WindowsSecurityMatchedScope{
				ScopeID:      fmt.Sprintf("scope-%d-%d", i, j),
				GovernedRoot: `C:\Test\Root`,
			}
		}
		pending[i] = securityBulkRecord{
			sourceRecordID: int64(i + 1),
			value: records.WindowsSecurityEventObservation{
				MatchedScopes: scopes,
			},
		}
	}
	return pending
}

var securityScopeRowBenchmarkSink int

// The benchmark includes creation of the legacy [][]any scope matrix.
// It excludes PostgreSQL execution, server WAL and transport costs.
func BenchmarkSecurityScopeCOPYRowsLegacyVsReusable(b *testing.B) {
	pending := scopeCopyBenchmarkFixture(4096)

	b.Run("legacy-materialized", func(b *testing.B) {
		b.ReportAllocs()
		var result int
		for n := 0; n < b.N; n++ {
			rows := legacySecurityScopeValues(pending)
			source := pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
				return rows[i], nil
			})
			for source.Next() {
				values, err := source.Values()
				if err != nil {
					b.Fatal(err)
				}
				result += values[1].(int) + len(values[2].(string))
			}
			if err := source.Err(); err != nil {
				b.Fatal(err)
			}
		}
		securityScopeRowBenchmarkSink = result
	})

	b.Run("reusable-source", func(b *testing.B) {
		b.ReportAllocs()
		var result int
		for n := 0; n < b.N; n++ {
			source := newSecurityScopeCopySource(pending)
			for source.Next() {
				values, err := source.Values()
				if err != nil {
					b.Fatal(err)
				}
				result += values[1].(int) + len(values[2].(string))
			}
			if err := source.Err(); err != nil {
				b.Fatal(err)
			}
		}
		securityScopeRowBenchmarkSink = result
	})
}
