// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
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
