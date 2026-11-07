// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// EXPERIMENTAL: reusable Security-event COPY row source. Explicitly gated
// to isolated, opted-in private W128/P3 recovery. Production and ordinary
// P3 retain the legacy callback until whole-window acceptance proves a gain.
package recordingest

import (
	"context"
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

type privateSecurityEventCopySourceContextKey struct{}

// WithPrivateSecurityEventCopySource arms a candidate for one explicitly
// isolated private recovery context. The selector below still checks the
// detached-field partition and P3 guards; this does not change production FI.
func WithPrivateSecurityEventCopySource(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, privateSecurityEventCopySourceContextKey{}, true)
}

// usePrivateSecurityEventCopySource rejects production P1, ordinary P3, and
// unflagged private W128/P3. No environment variables or global mutations.
func usePrivateSecurityEventCopySource(ctx context.Context) bool {
	return ctx != nil &&
		ctx.Value(privateSecurityEventCopySourceContextKey{}) == true &&
		privateSecurityFieldPartitionsEnabled(ctx) &&
		securityBulkLimitsFromContext(ctx).Name == "P3"
}
