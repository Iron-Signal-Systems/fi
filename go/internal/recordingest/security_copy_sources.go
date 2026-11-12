// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Bounded, allocation-conscious PostgreSQL COPY sources for already-decoded
// Security source records and matched governed scopes. These do not parse or
// revalidate JSON, mutate the signed input, or control SQL transactions.
package recordingest

import "errors"

// securitySourceCopySource emits the exact established nine parent columns.
// Each Values call returns an array reused by the subsequent Next/Values call.
// pgx CopyFrom consumes and encodes the row before requesting another row.
type securitySourceCopySource struct {
	pending       []securityBulkRecord
	sourceBatchID int64
	next          int
	values        [9]any
}

func newSecuritySourceCopySource(pending []securityBulkRecord, sourceBatchID int64) *securitySourceCopySource {
	return &securitySourceCopySource{pending: pending, sourceBatchID: sourceBatchID}
}

func (s *securitySourceCopySource) Next() bool {
	if s.next >= len(s.pending) {
		return false
	}
	s.next++
	return true
}

func (s *securitySourceCopySource) Values() ([]any, error) {
	if s.next <= 0 || s.next > len(s.pending) {
		return nil, errors.New("FI Security source COPY: Values called without a row")
	}
	p := &s.pending[s.next-1]
	s.values = [9]any{
		bulkSourceBatchID(p.sourceBatchID, s.sourceBatchID),
		p.ordinal, p.prepared.Record.Version, p.prepared.Record.RecordKind,
		p.prepared.Record.ScopeID, p.prepared.WrittenAtUTC,
		p.prepared.RecordBytes, p.digest, IngestVersion,
	}
	return s.values[:], nil
}

func (s *securitySourceCopySource) Err() error { return nil }

// securityScopeCopySource streams exact four-column matched scope records.
// The parent identity and 1-based ordinal are preserved without building a
// second [][]any allocation proportional to the number of matched scopes.
type securityScopeCopySource struct {
	pending    []securityBulkRecord
	eventIndex int
	scopeIndex int
	current    bool
	values     [4]any
}

func newSecurityScopeCopySource(pending []securityBulkRecord) *securityScopeCopySource {
	return &securityScopeCopySource{pending: pending}
}

func (s *securityScopeCopySource) Next() bool {
	for s.eventIndex < len(s.pending) {
		scopes := s.pending[s.eventIndex].value.MatchedScopes
		if s.scopeIndex < len(scopes) {
			scope := &scopes[s.scopeIndex]
			s.values = [4]any{
				s.pending[s.eventIndex].sourceRecordID,
				s.scopeIndex + 1, scope.ScopeID, scope.GovernedRoot,
			}
			s.scopeIndex++
			s.current = true
			return true
		}
		s.eventIndex++
		s.scopeIndex = 0
	}
	s.current = false
	return false
}

func (s *securityScopeCopySource) Values() ([]any, error) {
	if !s.current {
		return nil, errors.New("FI Security scope COPY: Values called without a row")
	}
	return s.values[:], nil
}

func (s *securityScopeCopySource) Err() error { return nil }
