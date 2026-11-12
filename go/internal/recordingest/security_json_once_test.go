// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// FI experimental canonical Security JSON-once acceptance tests.
package recordingest

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"reflect"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

// legacySecurityJSONSelection mirrors the pre-change envelope and full
// payload-json.Valid gates. This acceptance oracle must remain independent
// of findCanonicalSecurityEnvelopeKeys and the optimized implementation.
func legacySecurityJSONSelection(raw []byte) bool {
	if len(raw) < len(securityEnvelopePrefix)+len(securityPayloadKey)+2 ||
		!bytes.HasPrefix(raw, securityEnvelopePrefix) ||
		raw[len(raw)-1] != '\n' || raw[len(raw)-2] != '}' {
		return false
	}
	body := raw[:len(raw)-1]
	if bytes.Contains(body, []byte{'\n'}) {
		return false
	}
	written := bytes.Index(body, securityWrittenAtKey)
	payload := bytes.Index(body, securityPayloadKey)
	if written <= len(securityEnvelopePrefix) ||
		payload <= written+len(securityWrittenAtKey) ||
		bytes.Count(body, securityWrittenAtKey) != 1 ||
		bytes.Count(body, securityPayloadKey) != 1 {
		return false
	}
	scope := body[len(securityEnvelopePrefix):written]
	writtenAt := body[written+len(securityWrittenAtKey):payload]
	if len(scope) < 2 || scope[0] != '"' || scope[len(scope)-1] != '"' ||
		!json.Valid(scope) || len(writtenAt) < 2 || writtenAt[0] != '"' ||
		writtenAt[len(writtenAt)-1] != '"' || !json.Valid(writtenAt) {
		return false
	}
	rawPayload := body[payload+len(securityPayloadKey):len(body)-1]
	return len(rawPayload) != 0 && json.Valid(rawPayload)
}

func TestSecurityJSONOnceCanonicalEvidenceAndTypedParity(t *testing.T) {
	for _, fields := range []int{0, 1, 24, 96} {
		raw := singlePassSecurityTestRecord(t, fields, 8192)
		if !legacySecurityJSONSelection(raw) {
			t.Fatalf("fields=%d: canonical fixture was not accepted by original", fields)
		}
		want, err := prepareOwnedSourceRecord(raw)
		if err != nil { t.Fatal(err) }
		wantSecurity, err := prepareSecurityBulkRecord(1, want, want.RecordDigest[:])
		if err != nil { t.Fatal(err) }
		got, security, selected, err := tryPrepareSinglePassSecurity(raw)
		if err != nil || !selected {
			t.Fatalf("fields=%d: fast path selected=%t err=%v", fields, selected, err)
		}
		if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(security.value, wantSecurity.value) ||
			!reflect.DeepEqual(security.eventRecordID, wantSecurity.eventRecordID) ||
			security.eventID != wantSecurity.eventID ||
			!bytes.Equal(security.digest, wantSecurity.digest) {
			t.Fatalf("fields=%d: signed evidence or typed projection diverged", fields)
		}
	}
}

// This reproduces the missing conditions from real signed Security events.
// "version" and "scope_id" are valid NESTED payload members. Neither
// belongs to the spool envelope and neither may disable the one-pass path.
func TestSecurityJSONOnceNestedSecurityMembersRemainSelected(t *testing.T) {
	raw := singlePassSecurityTestRecord(t, 48, 8192)
	var record spool.Record
	if err := json.Unmarshal(raw[:len(raw)-1], &record); err != nil { t.Fatal(err) }
	var event records.WindowsSecurityEventObservation
	if err := json.Unmarshal(record.Payload, &event); err != nil { t.Fatal(err) }
	event.Version = "3"
	event.MatchedScopes = []records.WindowsSecurityMatchedScope{
		{ScopeID: "finance", GovernedRoot: `D:\Finance`},
		{ScopeID: "public", GovernedRoot: `D:\Public`},
	}
	payload, err := json.Marshal(event)
	if err != nil { t.Fatal(err) }
	record.Payload = payload
	encoded, err := json.Marshal(record)
	if err != nil { t.Fatal(err) }
	encoded = append(encoded, '\n')

	if !bytes.Contains(encoded, []byte(`"version":"3"`)) ||
		!bytes.Contains(encoded, []byte(`"scope_id":"finance"`)) {
		t.Fatal("missing nested Security test members")
	}
	if !legacySecurityJSONSelection(encoded) {
		t.Fatal("legacy fast path rejected a canonical nested Security record")
	}
	got, security, selected, err := tryPrepareSinglePassSecurity(encoded)
	if err != nil || !selected {
		t.Fatalf("nested Security disabled fast path: selected=%t err=%v", selected, err)
	}
	legacy, err := prepareOwnedSourceRecord(encoded)
	if err != nil { t.Fatal(err) }
	legacySecurity, err := prepareSecurityBulkRecord(1, legacy, legacy.RecordDigest[:])
	if err != nil { t.Fatal(err) }
	if !reflect.DeepEqual(got, legacy) ||
		!reflect.DeepEqual(security.value, legacySecurity.value) ||
		!reflect.DeepEqual(security.eventRecordID, legacySecurity.eventRecordID) ||
		!bytes.Equal(security.digest, legacySecurity.digest) {
		t.Fatal("nested Security changed exact bytes, digest, or relational values")
	}
}

// The sender validated the original JSON. Ingest still has to reject a
// malformed signed cache item; one strict decode is enough. None of these
// records may pass either decoder, and the Security path must not run a
// preliminary syntax-validation pass to discover that.
func TestSecurityJSONOnceStrictDecodeRejectsMalformedStrings(t *testing.T) {
	raw := singlePassSecurityTestRecord(t, 24, 8192)
	cases := []struct {
		name string
		needle []byte
		replacement []byte
	}{
		{"scope", []byte(`"scope_id":"test-scope"`), []byte(`"scope_id":"bad\\q"`)},
		{"written-at", []byte(`"written_at":"2026`), []byte(`"written_at":"\\q2026`)},
		{"payload", []byte(`"event_id":"4663"`), []byte(`"event_id":"bad\\q"`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !bytes.Contains(raw, tc.needle) { t.Fatal("fixture anchor missing") }
			mutated := bytes.Replace(raw, tc.needle, tc.replacement, 1)
			_, _, selected, err := tryPrepareSinglePassSecurity(mutated)
			if !selected || err == nil {
				t.Fatalf("malformed JSON reached successful fast path: selected=%t err_nil=%t", selected, err == nil)
			}
			if _, err := prepareOwnedSourceRecord(mutated); err == nil {
				t.Fatal("legacy strict decoder admitted malformed JSON")
			}
		})
	}
}

// Selection is allowed to be *more conservative* for abnormal signed JSON,
// but cannot accept an unsafe fast-path slice that was invalid under the
// original json.Valid gate. The fallback must preserve original acceptance,
// exact source bytes and typed relational values.
func TestSecurityJSONOnceNoncanonicalAndMalformedFallback(t *testing.T) {
	raw := singlePassSecurityTestRecord(t, 24, 8192)
	variants := [][]byte{
		bytes.Replace(raw, []byte("\"event_id\":\"4663\""), []byte("\"event_id\":false"), 1),
		bytes.Replace(raw, []byte("\"event_id\":\"4663\""), []byte("\"event_id\":\"\\q\""), 1),
		bytes.Replace(raw, []byte("\"scope_id\":\"test-scope\""), []byte("\"scope_id\":false"), 1),
		bytes.Replace(raw, []byte("\"event_id\":\"4663\""), []byte("\"event_id\":[}}"), 1),
		raw[:len(raw)-1],
	}
	for _, extra := range []string{
		",\"version\":\"fi-spool-record/0.1\"}",
		",\"Payload\":{}}",
		", \"payload\":{}}",
		",\"\\u0070ayload\":{}}",
		",\"P\\u0061yload\":{}}",
		",\"unknown\":{\"a\":1}}",
		",\"record_kind\":\"WindowsSecurityEvent\"}",
	} {
		record := append([]byte(nil), raw[:len(raw)-2]...)
		record = append(record, []byte(extra)...)
		variants = append(variants, append(record, '\n'))
	}
	rng := rand.New(rand.NewSource(20261111))
	for i := 0; i < 12000; i++ {
		record := append([]byte(nil), raw...)
		for j := 0; j <= i%2; j++ {
			record[rng.Intn(len(record))] = byte(rng.Intn(256))
		}
		variants = append(variants, record)
	}
	for i, record := range variants {
		originalFastSelection := legacySecurityJSONSelection(record)
		got, security, selected, fastErr := tryPrepareSinglePassSecurity(record)
		if selected && !originalFastSelection && fastErr == nil {
			t.Fatalf("case %d: fast-path accepted an input rejected by original syntax gate", i)
		}
		// Selection itself is an implementation detail. With redundant JSON
		// syntax prechecks removed, malformed canonical-shaped JSON may reach
		// the one strict decoder, but it MUST still be rejected.
		if selected {
			if fastErr == nil {
				legacy, err := prepareOwnedSourceRecord(record)
				if err != nil {
					t.Fatalf("case %d: fast path accepted input rejected by legacy: %v", i, err)
				}
				legacySecurity, err := prepareSecurityBulkRecord(1, legacy, legacy.RecordDigest[:])
				if err != nil || !reflect.DeepEqual(got, legacy) ||
					!reflect.DeepEqual(security.value, legacySecurity.value) {
					t.Fatalf("case %d: signed source/typed projection differs, err=%v", i, err)
				}
			}
			continue
		}
		if fastErr != nil {
			t.Fatalf("case %d: fallback returned an error: %v", i, fastErr)
		}
		// The same general decoder remains the fallback. It must never
		// bypass strict schema validation or event-record validation.
		legacy, err := prepareOwnedSourceRecord(record)
		if err != nil {
			continue
		}
		if legacy.Record.RecordKind == "WindowsSecurityEvent" {
			if _, err := prepareSecurityBulkRecord(1, legacy, legacy.RecordDigest[:]); err != nil {
				continue
			}
		}
	}
}

var securityJSONOnceBenchmarkSink int

func BenchmarkSecurityJSONOnceWholeRecord(b *testing.B) {
	raw := singlePassSecurityTestRecord(b, 24, 8192)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		source, security, selected, err := tryPrepareSinglePassSecurity(raw)
		if err != nil || !selected { b.Fatalf("selected=%t err=%v", selected, err) }
		securityJSONOnceBenchmarkSink = source.RecordBytes + len(security.value.Fields)
	}
}
