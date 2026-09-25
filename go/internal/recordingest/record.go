// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

const IngestVersion = "fi-postgresql-relational-ingest/0.2"

const SpoolRecordVersion = "fi-spool-record/0.1"

var supportedRecordKinds = map[string]struct{}{
	"CollectorIdentity":               {},
	"DirectoryPrincipalSnapshot":      {},
	"FileObservation":                 {},
	"LocalPrincipalSnapshot":          {},
	"NTFSCollectionError":             {},
	"SMBShareSnapshot":                {},
	"SupportingSourceCollectionError": {},
	"USNContinuityGap":                {},
	"USNObjectObservation":            {},
	"USNReadBoundary":                 {},
	"WindowsSecurityContinuityGap":    {},
	"WindowsSecurityCoverage":         {},
	"WindowsSecurityEvent":            {},
}

// SourceRecord is the validated common envelope and exact byte identity of one
// source JSONL record. PostgreSQL stores the byte count and SHA-256 lineage, not
// a second copy of these JSON bytes.
type SourceRecord struct {
	Record         spool.Record
	RawRecordBytes []byte
	RecordBytes    int
	RecordSHA256   string
	WrittenAtUTC   time.Time
}

// PrepareSourceRecord strictly validates the stable FI spool envelope. The
// input must be exactly one LF-terminated JSON object. The SHA-256 is over the
// exact JSONL bytes, including the final LF, so source_record can be proven
// against immutable recorder custody without storing the JSON again.
func PrepareSourceRecord(raw []byte) (SourceRecord, error) {
	if len(raw) == 0 {
		return SourceRecord{}, errors.New("FI ingest source record is empty")
	}
	if raw[len(raw)-1] != '\n' {
		return SourceRecord{}, errors.New("FI ingest source record is missing final LF")
	}
	if len(raw) == 1 {
		return SourceRecord{}, errors.New("FI ingest source record is empty")
	}

	body := raw[:len(raw)-1]
	if bytes.Contains(body, []byte{'\n'}) {
		return SourceRecord{}, errors.New("FI ingest source record contains embedded LF")
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()

	var record spool.Record
	if err := decoder.Decode(&record); err != nil {
		return SourceRecord{}, fmt.Errorf("decode FI ingest source record: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return SourceRecord{}, errors.New("FI ingest source record contains trailing JSON")
	}

	if record.Version != SpoolRecordVersion {
		return SourceRecord{}, fmt.Errorf("unsupported FI spool record version %q", record.Version)
	}
	if _, ok := supportedRecordKinds[record.RecordKind]; !ok {
		return SourceRecord{}, fmt.Errorf("unsupported FI source record kind %q", record.RecordKind)
	}
	if record.ScopeID == "" {
		return SourceRecord{}, errors.New("FI ingest source record scope ID is required")
	}
	if record.WrittenAt == "" {
		return SourceRecord{}, errors.New("FI ingest source record written_at is required")
	}
	if len(record.Payload) == 0 || !json.Valid(record.Payload) {
		return SourceRecord{}, errors.New("FI ingest source record payload JSON is required and must be valid")
	}

	writtenAt, err := time.Parse(time.RFC3339Nano, record.WrittenAt)
	if err != nil {
		return SourceRecord{}, fmt.Errorf("parse FI ingest source record written_at: %w", err)
	}

	digest := sha256.Sum256(raw)

	return SourceRecord{
		Record:         record,
		RawRecordBytes: append([]byte(nil), raw...),
		RecordBytes:    len(raw),
		RecordSHA256:   hex.EncodeToString(digest[:]),
		WrittenAtUTC:   writtenAt.UTC(),
	}, nil
}

// SupportedRecordKinds returns the complete collector-emitted record-kind set
// accepted by the relational ingester. A copy is returned so callers cannot
// change the ingest contract.
func SupportedRecordKinds() []string {
	return []string{
		"CollectorIdentity",
		"DirectoryPrincipalSnapshot",
		"FileObservation",
		"LocalPrincipalSnapshot",
		"NTFSCollectionError",
		"SMBShareSnapshot",
		"SupportingSourceCollectionError",
		"USNContinuityGap",
		"USNObjectObservation",
		"USNReadBoundary",
		"WindowsSecurityContinuityGap",
		"WindowsSecurityCoverage",
		"WindowsSecurityEvent",
	}
}
