// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestPrepareSourceRecordHashesExactJSONLBytes(t *testing.T) {
	raw := []byte(`{"version":"fi-spool-record/0.1","record_kind":"CollectorIdentity","scope_id":"root-1","written_at":"2026-09-19T16:00:00.123456700Z","payload":{"future_field":true}}` + "\n")

	got, err := PrepareSourceRecord(raw)
	if err != nil {
		t.Fatalf("PrepareSourceRecord() error = %v", err)
	}

	if string(got.RawRecordBytes) != string(raw) {
		t.Fatalf("exact JSONL bytes changed")
	}
	if got.RecordBytes != len(raw) {
		t.Fatalf("RecordBytes = %d, want %d", got.RecordBytes, len(raw))
	}

	digest := sha256.Sum256(raw)
	want := hex.EncodeToString(digest[:])
	if got.RecordSHA256 != want {
		t.Fatalf("RecordSHA256 = %q, want %q", got.RecordSHA256, want)
	}
	if got.RecordDigest != digest {
		t.Fatal("binary source record digest does not equal signed JSONL SHA-256")
	}
}

func TestPrepareSourceRecordRejectsMissingFinalLF(t *testing.T) {
	raw := []byte(`{"version":"fi-spool-record/0.1","record_kind":"CollectorIdentity","scope_id":"root-1","written_at":"2026-09-19T16:00:00Z","payload":{}}`)
	if _, err := PrepareSourceRecord(raw); err == nil {
		t.Fatal("PrepareSourceRecord() accepted missing final LF")
	}
}

func TestPrepareSourceRecordRejectsUnknownEnvelopeField(t *testing.T) {
	raw := []byte(`{"version":"fi-spool-record/0.1","record_kind":"CollectorIdentity","scope_id":"root-1","written_at":"2026-09-19T16:00:00Z","unexpected":1,"payload":{}}` + "\n")
	if _, err := PrepareSourceRecord(raw); err == nil {
		t.Fatal("PrepareSourceRecord() accepted unknown envelope field")
	}
}

func TestPrepareSourceRecordRejectsUnknownKind(t *testing.T) {
	raw := []byte(`{"version":"fi-spool-record/0.1","record_kind":"FutureThing","scope_id":"root-1","written_at":"2026-09-19T16:00:00Z","payload":{}}` + "\n")
	if _, err := PrepareSourceRecord(raw); err == nil {
		t.Fatal("PrepareSourceRecord() accepted unknown record kind")
	}
}

func TestSupportedRecordKindsExact(t *testing.T) {
	kinds := SupportedRecordKinds()
	if len(kinds) != 13 {
		t.Fatalf("supported kinds = %d, want 13", len(kinds))
	}
	joined := strings.Join(kinds, "\n")
	for _, want := range []string{
		"FileObservation",
		"USNObjectObservation",
		"WindowsSecurityEvent",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("supported kinds missing %q", want)
		}
	}
}

func TestOwnedSourceRecordAvoidsSecondRawCopyWithoutChangingEvidence(t *testing.T) {
	raw := []byte(`{"version":"fi-spool-record/0.1","record_kind":"WindowsSecurityEvent","scope_id":"root-1","written_at":"2026-11-03T10:00:00Z","payload":{"fields":[{"name":"FileName","value":"C:\\\\test.txt"}],"raw_xml":"<Event/>"}}` + "\n")
	baseline, err := PrepareSourceRecord(raw)
	if err != nil { t.Fatal(err) }
	owned, err := prepareOwnedSourceRecord(raw)
	if err != nil { t.Fatal(err) }
	if owned.RecordSHA256 != baseline.RecordSHA256 || owned.RecordDigest != baseline.RecordDigest || owned.RecordBytes != baseline.RecordBytes ||
	   !bytes.Equal(owned.Record.Payload, baseline.Record.Payload) {
		t.Fatal("owned real-ingest record changed signed envelope or digest")
	}
	if &owned.RawRecordBytes[0] != &raw[0] {
		t.Fatal("owned real-ingest record unexpectedly copied immutable reader bytes")
	}
	if &baseline.RawRecordBytes[0] == &raw[0] {
		t.Fatal("external PrepareSourceRecord no longer isolates caller mutation")
	}
	raw[0] ^= 1
	if baseline.RawRecordBytes[0] != '{' {
		t.Fatal("public SourceRecord evidence alias changed")
	}
}

func TestOwnedSourceRecordStillRejectsMalformedNestedPayload(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"version":"fi-spool-record/0.1","record_kind":"WindowsSecurityEvent","scope_id":"root-1","written_at":"2026-11-03T10:00:00Z","payload":{"fields":[invalid]}}`+"\n"),
		[]byte(`{"version":"fi-spool-record/0.1","record_kind":"WindowsSecurityEvent","scope_id":"root-1","written_at":"2026-11-03T10:00:00Z","payload":}`+"\n"),
	}
	for _, raw := range cases {
		if _, err := prepareOwnedSourceRecord(raw); err == nil {
			t.Fatalf("malformed payload accepted: %s", raw)
		}
	}
}
