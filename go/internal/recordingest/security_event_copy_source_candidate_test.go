// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"crypto/sha256"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// legacySecurityEventCopyValues mirrors the active security_bulk.go callback;
// the candidate must be value- and type-identical at all forty positions.
func legacySecurityEventCopyValues(p securityBulkRecord) []any {
	v := p.value
	rawXML := []byte(v.RawXML)
	digest := sha256.Sum256(rawXML)
	return []any{
		p.sourceRecordID, p.observedAt, v.CollectionMethod, v.Channel, v.Provider, p.eventID,
		nullString(v.Version), p.eventRecordID, p.timeCreated, v.Computer, nullString(v.Keywords),
		string(v.AuditResult), string(v.ScopeBasis), nullString(v.SubjectUserSID),
		nullString(v.SubjectUserName), nullString(v.SubjectDomainName), nullString(v.SubjectLogonID),
		nullString(v.ObjectServer), nullString(v.ObjectType), nullString(v.ObjectName),
		nullString(v.HandleID), nullString(v.ProcessID), nullString(v.ProcessName),
		nullString(v.AccessMask), nullString(v.AccessList), nullString(v.AccessReason),
		nullString(v.TransactionID), nullString(v.FileName), nullString(v.LinkName),
		nullString(v.SourceIP), nullString(v.SourcePort), nullString(v.ShareName),
		nullString(v.ShareLocalPath), nullString(v.RelativeTargetName),
		nullString(v.OldSecurityDescriptor), nullString(v.NewSecurityDescriptor),
		nullString(v.SubcategoryGUID), nullString(v.AuditPolicyChanges),
		len(rawXML), digest[:],
	}
}

func candidateSecurityEventFixture(count int) []securityBulkRecord {
	events := make([]securityBulkRecord, count)
	now := time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
	for i := range events {
		v := records.WindowsSecurityEventObservation{
			CollectionMethod: records.WindowsSecurityCollectionMethod,
			Channel: "Security", Provider: "Microsoft-Windows-Security-Auditing",
			Computer: "test.iss.local", AuditResult: records.WindowsSecurityAuditSuccess,
			ScopeBasis: records.WindowsSecurityScopePathMatched,
			RawXML: "<Event><Data>" + strings.Repeat("abc&<>", 32) + "</Data></Event>",
		}
		if i%2 == 0 {
			v.Version = "0"
			v.Keywords = "Audit Success"
			v.SubjectUserSID = "S-1-5-18"
			v.ObjectName = "C:\\folder\\file.txt"
			v.FileName = v.ObjectName
			v.SourceIP = "192.0.2.10"
			v.AuditPolicyChanges = "success"
		}
		if i%3 == 0 {
			v.RawXML = "<Event>\u00e9\\x01" + strings.Repeat("data", 50) + "</Event>"
		}
		events[i] = securityBulkRecord{
			sourceRecordID: int64(100 + i),
			observedAt: now.Add(time.Duration(i)*time.Second),
			timeCreated: now,
			eventID: 4663,
			eventRecordID: pgtype.Numeric{Int: big.NewInt(int64(1<<40) + int64(i)), Exp: 0, Valid: true},
			value: v,
		}
	}
	return events
}

func TestSecurityEventReusableCOPYSourceMatchesLegacyFortyColumns(t *testing.T) {
	pending := candidateSecurityEventFixture(9)
	source := newSecurityEventCopySource(pending)
	if _, err := source.Values(); err == nil {
		t.Fatal("Values before Next succeeded")
	}
	for i := range pending {
		if !source.Next() {
			t.Fatalf("missing event row %d", i)
		}
		got, err := source.Values()
		if err != nil {
			t.Fatal(err)
		}
		want := legacySecurityEventCopyValues(pending[i])
		if len(got) != 40 || len(want) != 40 {
			t.Fatalf("row %d invalid column count: got=%d legacy=%d", i, len(got), len(want))
		}
		for j := range got {
			if !reflect.DeepEqual(got[j], want[j]) {
				t.Fatalf("row %d column %d diverged: got=%#v (%T), want=%#v (%T)", i, j, got[j], got[j], want[j], want[j])
			}
		}
		if got[0] != pending[i].sourceRecordID {
			t.Fatalf("wrong source identity at row %d", i)
		}
	}
	if source.Next() {
		t.Fatal("source produced additional event row")
	}
	if err := source.Err(); err != nil {
		t.Fatal(err)
	}
}

var securityEventRowBenchmarkSink int

func BenchmarkSecurityEventCOPYRowsLegacyVsReusable(b *testing.B) {
	pending := candidateSecurityEventFixture(4096)
	b.Run("legacy-slice", func(b *testing.B) {
		b.ReportAllocs()
		var result int
		for n := 0; n < b.N; n++ {
			rows := pgx.CopyFromSlice(len(pending), func(i int) ([]any, error) {
				return legacySecurityEventCopyValues(pending[i]), nil
			})
			for rows.Next() {
				vals, err := rows.Values()
				if err != nil { b.Fatal(err) }
				result += len(vals) + int(vals[39].([]byte)[0])
			}
			if err := rows.Err(); err != nil { b.Fatal(err) }
		}
		securityEventRowBenchmarkSink = result
	})
	b.Run("reusable-source", func(b *testing.B) {
		b.ReportAllocs()
		var result int
		for n := 0; n < b.N; n++ {
			rows := newSecurityEventCopySource(pending)
			for rows.Next() {
				vals, err := rows.Values()
				if err != nil { b.Fatal(err) }
				result += len(vals) + int(vals[39].([]byte)[0])
			}
			if err := rows.Err(); err != nil { b.Fatal(err) }
		}
		securityEventRowBenchmarkSink = result
	})
}

func TestSecurityEventReusableCOPYSourcePrivateProfileGate(t *testing.T) {
	// The production P1 default and ordinary P3 must never select the
	// experimental row source, even though they share the bulk writer.
	pending := candidateSecurityEventFixture(3)
	if _, ok := securityEventCopyRows(context.Background(), pending).(*securityEventCopySource); ok {
		t.Fatal("production default unexpectedly selected the experimental Security COPY source")
	}
	p3, err := withFixedSecurityBulkProfile(context.Background(), "P3")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := securityEventCopyRows(p3, pending).(*securityEventCopySource); ok {
		t.Fatal("ordinary P3 unexpectedly selected the experimental Security COPY source")
	}
	private := WithPrivateSecurityFieldPartitions(p3)
	source, ok := securityEventCopyRows(private, pending).(*securityEventCopySource)
	if !ok {
		t.Fatal("private-field P3 did not select the reusable Security COPY source")
	}
	for i := range pending {
		if !source.Next() {
			t.Fatalf("private Security COPY missed event row %d", i)
		}
		got, err := source.Values()
		if err != nil {
			t.Fatal(err)
		}
		want := legacySecurityEventCopyValues(pending[i])
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("private Security COPY row %d differed from the legacy forty-column row", i)
		}
	}
	if source.Next() {
		t.Fatal("private Security COPY generated extra event rows")
	}
}
