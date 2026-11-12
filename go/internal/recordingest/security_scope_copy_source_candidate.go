// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// EXPERIMENTAL: allocation-bounded Windows Security matched-scope COPY rows.
// This source is selected only by the private W128/P3 replay. Production
// Security ingestion continues to use the original materialized row slice.
package recordingest

import "errors"

// securityScopeCopySource traverses already validated Security parent records
// in their original event/scope order, without allocating a [][]any matrix.
// It reuses one four-column row; pgx.CopyFrom must encode Values before
// calling Next again, as required by the pgx.CopyFromSource contract.
//
// This source does not own a transaction, change validation, or alter scope
// ordinals. A parent with zero scopes yields zero rows.
type securityScopeCopySource struct {
	pending    []securityBulkRecord
	eventIndex int
	scopeIndex int
	ready      bool
	row        [4]any
}

func newSecurityScopeCopySource(pending []securityBulkRecord) *securityScopeCopySource {
	return &securityScopeCopySource{pending: pending}
}

// Next advances past empty parents and presents exactly one scope per call.
// The ordinal is one-based within each event, matching the legacy COPY input.
func (s *securityScopeCopySource) Next() bool {
	s.ready = false
	for s.eventIndex < len(s.pending) {
		parent := &s.pending[s.eventIndex]
		if s.scopeIndex < len(parent.value.MatchedScopes) {
			scope := &parent.value.MatchedScopes[s.scopeIndex]
			s.row[0] = parent.sourceRecordID
			s.row[1] = s.scopeIndex + 1
			s.row[2] = scope.ScopeID
			s.row[3] = scope.GovernedRoot
			s.scopeIndex++
			s.ready = true
			return true
		}
		s.eventIndex++
		s.scopeIndex = 0
	}
	return false
}

// Values exposes the current row only after a successful Next call.
// No retained reference to this row is permitted across the next Next call.
func (s *securityScopeCopySource) Values() ([]any, error) {
	if !s.ready {
		return nil, errors.New("FI Security scope COPY: Values called without a row")
	}
	return s.row[:], nil
}

func (s *securityScopeCopySource) Err() error { return nil }
