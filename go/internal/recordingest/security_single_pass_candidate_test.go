// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func singlePassSecurityTestRecord(t testing.TB, fields int, rawXMLSize int) []byte {
	t.Helper()
	now := time.Date(2026,11,5,11,0,0,0,time.UTC).Format(time.RFC3339Nano)
	v := records.WindowsSecurityEventObservation{
		ObservedAt: now, CollectionMethod: records.WindowsSecurityCollectionMethod,
		Channel: "Security", Provider: "Microsoft-Windows-Security-Auditing",
		EventID: "4663", EventRecordID: "18446744073709551615",
		TimeCreated: now, Computer: "iss-fs-22a.iss.local",
		AuditResult: records.WindowsSecurityAuditSuccess,
		ScopeBasis: records.WindowsSecurityScopePathMatched,
		SubjectUserSID: "S-1-5-18", ObjectName: `C:\audit\events.log`,
		RawXML: "<Event>" + strings.Repeat("event-data-&amp;",rawXMLSize/15) + "</Event>",
	}
	for j:=0;j<fields;j++ {
		v.Fields=append(v.Fields,records.WindowsSecurityEventField{
			Name:"Field",Value:strings.Repeat("value",8),
		})
	}
	payload,err:=json.Marshal(v)
	if err!=nil {t.Fatal(err)}
	raw,err:=json.Marshal(spool.Record{
		Version:SpoolRecordVersion, RecordKind:"WindowsSecurityEvent",
		ScopeID:"test-scope",WrittenAt:now,Payload:payload,
	})
	if err!=nil {t.Fatal(err)}
	return append(raw,'\n')
}

func TestSinglePassSecurityCanonicalEquivalence(t *testing.T) {
	for _,fields:=range []int{0,1,24,96} {
		raw:=singlePassSecurityTestRecord(t,fields,8192)
		original,err:=prepareOwnedSourceRecord(raw)
		if err!=nil {t.Fatal(err)}
		legacy,err:=prepareSecurityBulkRecord(1,original,original.RecordDigest[:])
		if err!=nil {t.Fatal(err)}
		got,fast,selected,err:=tryPrepareSinglePassSecurity(raw)
		if err!=nil || !selected {t.Fatalf("fields=%d selected=%t err=%v",fields,selected,err)}
		if !reflect.DeepEqual(got,original) {
			t.Fatalf("fields=%d envelope or byte identity changed",fields)
		}
		if !reflect.DeepEqual(fast.value,legacy.value) ||
			!fast.observedAt.Equal(legacy.observedAt) ||
			!fast.timeCreated.Equal(legacy.timeCreated) ||
			fast.eventID!=legacy.eventID ||
			!reflect.DeepEqual(fast.eventRecordID,legacy.eventRecordID) ||
			!bytes.Equal(fast.digest,legacy.digest) {
			t.Fatalf("fields=%d typed projection diverged",fields)
		}
	}
}

func TestSinglePassSecurityFallbackAndReject(t *testing.T) {
	raw:=singlePassSecurityTestRecord(t,3,2048)
	cases:=[]struct{name string;data []byte;selected bool;success bool}{
		{"normal",raw,true,true},
		{"non-security",bytes.Replace(raw,[]byte(`"WindowsSecurityEvent"`),[]byte(`"FileObservation"`),1),false,false},
		{"reordered",bytes.Replace(raw,[]byte(`,"written_at":`),[]byte(`,"alias":123,"written_at":`),1),false,false},
		{"missing-LF",raw[:len(raw)-1],false,false},
		{"invalid-body",bytes.Replace(raw,[]byte(`"event_id":"4663"`),[]byte(`"event_id":false`),1),true,false},
	}
	for _,tt:=range cases {t.Run(tt.name,func(t *testing.T){
		_,_,selected,err:=tryPrepareSinglePassSecurity(tt.data)
		if selected!=tt.selected {t.Fatalf("selected=%v want=%v",selected,tt.selected)}
		if (err==nil)!=tt.success && selected {t.Fatalf("error=%v wantSuccess=%v",err,tt.success)}
	})}
}

var singlePassSecurityBenchmarkSink int

func BenchmarkSecuritySourceEnvelopeAndPayloadOnePass(b *testing.B) {
	raw:=singlePassSecurityTestRecord(b,24,8192)
	b.Run("current-two-pass",func(b *testing.B){
		b.ReportAllocs()
		var sink int
		for i:=0;i<b.N;i++ {
			source,err:=prepareOwnedSourceRecord(raw)
			if err!=nil {b.Fatal(err)}
			p,err:=prepareSecurityBulkRecord(1,source,source.RecordDigest[:])
			if err!=nil {b.Fatal(err)}
			sink+=len(p.value.Fields)+p.prepared.RecordBytes
		}
		singlePassSecurityBenchmarkSink=sink
	})
	b.Run("candidate-single-pass",func(b *testing.B){
		b.ReportAllocs()
		var sink int
		for i:=0;i<b.N;i++ {
			s,p,selected,err:=tryPrepareSinglePassSecurity(raw)
			if err!=nil || !selected {b.Fatalf("selected=%t err=%v",selected,err)}
			sink+=len(p.value.Fields)+s.RecordBytes
		}
		singlePassSecurityBenchmarkSink=sink
	})
}
