// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// EXPERIMENTAL: reusable nine-column source_record COPY values. Only the
// isolated private W128/P3 replay selects these sources. Ordinary ingestion
// keeps its existing pgx.CopyFromSlice callbacks.
package recordingest

import "errors"

// sourceRecordCopyRow holds the same nine values and types as the existing
// Security/File source-record callbacks. All values refer to already validated
// evidence, including the original signed SHA-256 digest.
//
// pgx.CopyFrom consumes Values synchronously before advancing Next. Reusing
// this row therefore avoids a []any allocation per source record without
// changing row identity or serialization order.
type sourceRecordCopyRow struct {
	values [9]any
}

func (row *sourceRecordCopyRow) assign(batchID, ordinal int64, prepared *SourceRecord, digest []byte) {
	row.values[0] = batchID
	row.values[1] = ordinal
	row.values[2] = prepared.Record.Version
	row.values[3] = prepared.Record.RecordKind
	row.values[4] = prepared.Record.ScopeID
	row.values[5] = prepared.WrittenAtUTC
	row.values[6] = prepared.RecordBytes
	row.values[7] = digest
	row.values[8] = IngestVersion
}

// securitySourceRecordCopySource streams source_record rows for validated
// Security events. It does not resolve database-generated IDs or own a TX.
type securitySourceRecordCopySource struct {
	pending      []securityBulkRecord
	sourceBatchID int64
	offset       int
	ready        bool
	row          sourceRecordCopyRow
}

func newSecuritySourceRecordCopySource(pending []securityBulkRecord, sourceBatchID int64) *securitySourceRecordCopySource {
	return &securitySourceRecordCopySource{pending: pending, sourceBatchID: sourceBatchID}
}

func (s *securitySourceRecordCopySource) Next() bool {
	s.ready = false
	if s.offset >= len(s.pending) {
		return false
	}
	p := &s.pending[s.offset]
	s.row.assign(bulkSourceBatchID(p.sourceBatchID, s.sourceBatchID),
		p.ordinal, &p.prepared, p.digest)
	s.offset++
	s.ready = true
	return true
}

func (s *securitySourceRecordCopySource) Values() ([]any, error) {
	if !s.ready {
		return nil, errors.New("FI Security source COPY: Values called without a row")
	}
	return s.row.values[:], nil
}

func (s *securitySourceRecordCopySource) Err() error { return nil }

// fileSourceRecordCopySource uses the identical nine-column row contract for
// FileObservation and USNObjectObservation source envelopes. Per-batch ordinal
// and source ID mapping checks still run in copyFileSourceBulk.
type fileSourceRecordCopySource struct {
	pending       []fileSourceBulkRecord
	sourceBatchID int64
	offset        int
	ready         bool
	row           sourceRecordCopyRow
}

func newFileSourceRecordCopySource(pending []fileSourceBulkRecord, sourceBatchID int64) *fileSourceRecordCopySource {
	return &fileSourceRecordCopySource{pending: pending, sourceBatchID: sourceBatchID}
}

func (s *fileSourceRecordCopySource) Next() bool {
	s.ready = false
	if s.offset >= len(s.pending) {
		return false
	}
	p := &s.pending[s.offset]
	s.row.assign(bulkSourceBatchID(p.sourceBatchID, s.sourceBatchID),
		p.ordinal, &p.prepared, p.digest)
	s.offset++
	s.ready = true
	return true
}

func (s *fileSourceRecordCopySource) Values() ([]any, error) {
	if !s.ready {
		return nil, errors.New("FI FileObservation source COPY: Values called without a row")
	}
	return s.row.values[:], nil
}

func (s *fileSourceRecordCopySource) Err() error { return nil }
