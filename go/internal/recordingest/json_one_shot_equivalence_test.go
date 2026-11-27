// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

// Keep the original streaming Decoder as an acceptance/value oracle.
func legacyFIJSONStrictDecode(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func TestFIJSONOneShotPayloadMatchesStreamingStrictness(t *testing.T) {
	type sample struct {
		Name string `json:"name"`
		Nested struct {
			Value string `json:"value"`
		} `json:"nested"`
	}
	cases := []struct {
		label string
		raw string
	}{
		{"simple", `{"name":"ok","nested":{"value":"ok"}}`},
		{"escaped", `{"name":"line\n\u00e9","nested":{"value":"\u003cEvent/\u003e"}}`},
		{"duplicate", `{"name":"a","name":"b","nested":{"value":"ok"}}`},
		{"case-fold", `{"NAME":"ok","nested":{"VALUE":"ok"}}`},
		{"top-unknown", `{"name":"ok","extra":3,"nested":{"value":"ok"}}`},
		{"nested-unknown", `{"name":"ok","nested":{"value":"ok","extra":3}}`},
		{"trailing-value", `{"name":"ok","nested":{"value":"ok"}} {}`},
		{"trailing-garbage", `{"name":"ok","nested":{"value":"ok"}} x`},
		{"wrong-type", `{"name":false,"nested":{"value":"ok"}}`},
		{"valid-whitespace", `{"name":"ok","nested":{"value":"ok"}}` + " \t\r"},
		{"malformed", `{"name":"ok","nested":{"value":}}`},
	}
	for _, tc := range cases {
		t.Run(tc.label, func(t *testing.T) {
			var old, candidate sample
			legacyErr := legacyFIJSONStrictDecode([]byte(tc.raw), &old)
			candidateErr := decodeStrictPayload(json.RawMessage(tc.raw), &candidate)
			if (legacyErr == nil) != (candidateErr == nil) {
				t.Fatalf("acceptance differs: legacy=%v candidate=%v", legacyErr, candidateErr)
			}
			if legacyErr == nil && !reflect.DeepEqual(old, candidate) {
				t.Fatalf("values differ: legacy=%+v candidate=%+v", old, candidate)
			}
		})
	}
	// v1 permits invalid UTF-8 and replaces it. DefaultOptionsV1 must
	// retain that established behavior (while preserving signed raw bytes).
	raw := append([]byte(`{"name":"`), 0xff)
	raw = append(raw, []byte(`","nested":{"value":"ok"}}`)...)
	var old, candidate sample
	errOld := legacyFIJSONStrictDecode(raw, &old)
	errCandidate := decodeStrictPayload(raw, &candidate)
	if (errOld == nil) != (errCandidate == nil) || (errOld == nil && !reflect.DeepEqual(old, candidate)) {
		t.Fatalf("invalid UTF-8 compatibility: legacy=%v candidate=%v old=%+v new=%+v", errOld, errCandidate, old, candidate)
	}
}

func TestFIJSONOneShotEnvelopePreservesRawAndDigest(t *testing.T) {
	raw := []byte(`{"version":"fi-spool-record/0.1","record_kind":"WindowsSecurityEvent","scope_id":"scope-a","written_at":"2026-11-03T12:00:00Z","payload":{"fields":[{"name":"XML","value":"\u003cEvent/\u003e"}],"raw_xml":"<Event/>"}}` + "\n")
	var old spool.Record
	if err := legacyFIJSONStrictDecode(raw[:len(raw)-1], &old); err != nil {
		t.Fatal(err)
	}
	got, err := prepareOwnedSourceRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Record, old) || !bytes.Equal(got.RawRecordBytes, raw) {
		t.Fatal("signed source envelope or raw evidence changed")
	}
	if sum := sha256.Sum256(raw); got.RecordDigest != sum {
		t.Fatal("signed exact-byte SHA-256 changed")
	}
}

func BenchmarkFIJSONOneShotVsStreaming(b *testing.B) {
	type payload struct {
		Name string `json:"name"`
		Nested struct {
			Value string `json:"value"`
		} `json:"nested"`
	}
	input := []byte(`{"name":"` + strings.Repeat("ABCD", 4096) + `","nested":{"value":"ok"}}`)
	b.Run("streaming", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var value payload
			if err := legacyFIJSONStrictDecode(input, &value); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("one-shot", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var value payload
			if err := decodeStrictPayload(input, &value); err != nil {
				b.Fatal(err)
			}
		}
	})
}
