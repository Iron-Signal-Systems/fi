// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// EXPERIMENTAL: unconnected Security event COPY row source. Keep the legacy
// ingestion callback in security_bulk.go until value/SQL correctness and
// unprofiled W128 throughput justify replacing it.
package recordingest

import (
	"crypto/sha256"
	"errors"
)

// securityEventCopySource presents the exact existing forty relational
// Security event columns in source order. It reuses the array and digest
// storage; pgx CopyFrom must encode each row before requesting the next.
// It does not change signed source evidence or the transaction boundary.
type securityEventCopySource struct {
	pending []securityBulkRecord
	offset  int
	row     [40]any
	digest  [32]byte
}

func newSecurityEventCopySource(pending []securityBulkRecord) *securityEventCopySource {
	return &securityEventCopySource{pending: pending}
}

func (s *securityEventCopySource) Next() bool {
	if s.offset >= len(s.pending) {
		return false
	}
	s.offset++
	return true
}

func (s *securityEventCopySource) Values() ([]any, error) {
	if s.offset <= 0 || s.offset > len(s.pending) {
		return nil, errors.New("FI Security event COPY: Values called without a row")
	}
	p := &s.pending[s.offset-1]
	v := &p.value
	s.digest = sha256.Sum256([]byte(v.RawXML))
	s.row = [40]any{
		p.sourceRecordID, p.observedAt, v.CollectionMethod, v.Channel, v.Provider,
		p.eventID, nullString(v.Version), p.eventRecordID, p.timeCreated,
		v.Computer, nullString(v.Keywords), string(v.AuditResult), string(v.ScopeBasis),
		nullString(v.SubjectUserSID), nullString(v.SubjectUserName),
		nullString(v.SubjectDomainName), nullString(v.SubjectLogonID),
		nullString(v.ObjectServer), nullString(v.ObjectType), nullString(v.ObjectName),
		nullString(v.HandleID), nullString(v.ProcessID), nullString(v.ProcessName),
		nullString(v.AccessMask), nullString(v.AccessList), nullString(v.AccessReason),
		nullString(v.TransactionID), nullString(v.FileName), nullString(v.LinkName),
		nullString(v.SourceIP), nullString(v.SourcePort), nullString(v.ShareName),
		nullString(v.ShareLocalPath), nullString(v.RelativeTargetName),
		nullString(v.OldSecurityDescriptor), nullString(v.NewSecurityDescriptor),
		nullString(v.SubcategoryGUID), nullString(v.AuditPolicyChanges),
		len(v.RawXML), s.digest[:],
	}
	return s.row[:], nil
}

func (s *securityEventCopySource) Err() error { return nil }
