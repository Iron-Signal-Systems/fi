// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Experimental strict equivalence gate for the Security envelope key scanner.
package recordingest

import (
	"bytes"
	"math/rand"
	"testing"
)

// Reference exactly reproduces the former two Index + two Count predicates.
// It is intentionally kept independent of the candidate's implementation.
// Validation and signed-evidence semantics are unchanged by the optimization.
func legacySinglePassSecurityEnvelopeKeys(body []byte) (writtenAt, payload int, unique bool) {
	writtenAt = bytes.Index(body, securityWrittenAtKey)
	payload = bytes.Index(body, securityPayloadKey)
	if bytes.Count(body, securityWrittenAtKey) != 1 ||
		bytes.Count(body, securityPayloadKey) != 1 {
		return -1, -1, false
	}
	return writtenAt, payload, true
}

func compareSinglePassSecurityKeyScan(t *testing.T, name string, body []byte) {
	t.Helper()
	oldWritten, oldPayload, oldUnique := legacySinglePassSecurityEnvelopeKeys(body)
	newWritten, newPayload, newUnique := findSinglePassSecurityEnvelopeKeys(body)
	if oldUnique != newUnique {
		t.Fatalf("%s: uniqueness differs: old=%t new=%t body=%q",
			name, oldUnique, newUnique, body)
	}
	if oldUnique && (oldWritten != newWritten || oldPayload != newPayload) {
		t.Fatalf("%s: marker offsets changed: old=(%d,%d) new=(%d,%d)",
			name, oldWritten, oldPayload, newWritten, newPayload)
	}
}

func TestSinglePassSecurityEnvelopeKeyScanLegacyEquivalence(t *testing.T) {
	canonical := singlePassSecurityTestRecord(t, 24, 8192)
	if len(canonical) < 3 || canonical[len(canonical)-1] != '\n' {
		t.Fatal("invalid signed canonical Security fixture")
	}
	body := canonical[:len(canonical)-1]

	cases := []struct {
		name string
		body []byte
	}{
		{"canonical", body},
		{"empty", nil},
		{"absent", []byte(`{"version":1,"field":"value"}`)},
		{"only-written", []byte(`{"written_at":"2026-11-09T10:00:00Z"}`)},
		{"only-payload", []byte(`{"payload":{}}`)},
		{"reverse-order", []byte(`{"payload":{},"written_at":"now"}`)},
		{"duplicate-written", append(append([]byte(nil), body...), []byte(`,"written_at":"second"`)... )},
		{"duplicate-payload", append(append([]byte(nil), body...), []byte(`,"payload":{}`)... )},
		{"nested-written", []byte(`{"written_at":"now","payload":{"other":1,"written_at":"again"}}`)},
		{"nested-payload", []byte(`{"written_at":"now","payload":{"other":1,"payload":{}}}`)},
		{"quoted-marker-bytes", []byte(`{"written_at":"now","payload":"a,` + `"payload":` + `b"}`)},
		{"embedded-NUL", []byte{'a', ',', '"', 'p', 'a', 'y', 'l', 'o', 'a', 'd', '"', ':', 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compareSinglePassSecurityKeyScan(t, tc.name, tc.body)
		})
	}

	// Deterministic randomized byte strings exercise overlapping comma,
	// quote, escape and partial-marker behavior independent of JSON validity.
	rng := rand.New(rand.NewSource(20261109))
	alphabet := []byte{',', '"', 'w', 'p', 'a', 'y', 'l', 'o', 'd', 'r', 'i', 't',
		'e', 'n', '_', ':', '{', '}', '\\', '/', 'x', '0', 0, '\n'}
	for i := 0; i < 8000; i++ {
		size := rng.Intn(1024)
		probe := make([]byte, size)
		for j := range probe {
			probe[j] = alphabet[rng.Intn(len(alphabet))]
		}
		if size > 64 {
			// Force the scanner to see both markers in either order and
			// sometimes a second copy of either marker.
			markers := [][]byte{securityWrittenAtKey, securityPayloadKey}
			for _, marker := range markers {
				at := rng.Intn(size - len(marker) + 1)
				copy(probe[at:], marker)
			}
		}
		compareSinglePassSecurityKeyScan(t, "random", probe)
	}
}

var singlePassKeyScanBenchmarkSink int

func BenchmarkSinglePassSecurityEnvelopeKeySearch(b *testing.B) {
	for _, tc := range []struct {
		name   string
		fields int
		rawXML int
	}{
		{"8KiB", 24, 8192},
		{"64KiB", 96, 65536},
	} {
		b.Run(tc.name, func(b *testing.B) {
			raw := singlePassSecurityTestRecord(b, tc.fields, tc.rawXML)
			body := raw[:len(raw)-1]

			b.Run("legacy-four-searches", func(b *testing.B) {
				b.ReportAllocs()
				var sink int
				for i := 0; i < b.N; i++ {
					written := bytes.Index(body, securityWrittenAtKey)
					payload := bytes.Index(body, securityPayloadKey)
					if bytes.Count(body, securityWrittenAtKey) != 1 ||
						bytes.Count(body, securityPayloadKey) != 1 {
						b.Fatal("canonical Security fixture lost its unique markers")
					}
					sink += written + payload
				}
				singlePassKeyScanBenchmarkSink = sink
			})
			b.Run("single-comma-scan", func(b *testing.B) {
				b.ReportAllocs()
				var sink int
				for i := 0; i < b.N; i++ {
					written, payload, ok := findSinglePassSecurityEnvelopeKeys(body)
					if !ok {
						b.Fatal("canonical Security fixture rejected")
					}
					sink += written + payload
				}
				singlePassKeyScanBenchmarkSink = sink
			})
		})
	}
}
