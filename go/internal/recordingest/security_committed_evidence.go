// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// This file exposes committed Security ingestion measurements to the FreeBSD
// worker. It does not select profiles, collect resource pressure, or write SQL.
package recordingest

import "time"

// CommittedSecurityIngestMetrics describes one successfully committed relational
// generation containing Windows Security events. A nil result means no eligible
// committed Security measurement exists; consumers must never infer a zero-cost
// or successful generation from nil.
//
// SourceBytes counts the recorded WindowsSecurityEvent source record bytes.
// MaxContiguousSecurity is bounded within one signed source batch; it does not
// combine runs across source batches, even within the same generation.
// Duration covers the complete relational ingestion through confirmed COMMIT.
// It is not an isolated PostgreSQL COPY or CPU timing measurement.
type CommittedSecurityIngestMetrics struct {
	Profile               string
	Events                int64
	Fields                int64
	SourceBytes           int64
	MaxContiguousSecurity int
	Duration              time.Duration
}

// committedSecurityIngestMetrics returns a fresh immutable-by-convention value
// only after the caller has received a successful pgx transaction COMMIT. This
// function deliberately rejects AlreadyAccepted, rejected, inconsistent, or
// Security-free generations. Rejection and retry never create performance wins.
func committedSecurityIngestMetrics(
	result IngestResult,
	profile *ingestStageProfile,
	limits securityBulkLimits,
	duration time.Duration,
) *CommittedSecurityIngestMetrics {
	if result.Outcome != "Accepted" || profile == nil ||
		result.RecordsCommitted <= 0 ||
		result.RecordsSeen != result.RecordsCommitted ||
		limits.Name == "" || duration <= 0 {
		return nil
	}
	s := profile.SecurityBulk
	if s.Events <= 0 || s.Events > result.RecordsCommitted ||
		s.Fields < 0 || s.SourceBytes <= 0 ||
		s.MaxContiguousSecurity <= 0 || int64(s.MaxContiguousSecurity) > s.Events {
		return nil
	}
	return &CommittedSecurityIngestMetrics{
		Profile: limits.Name, Events: s.Events, Fields: s.Fields,
		SourceBytes:           s.SourceBytes,
		MaxContiguousSecurity: s.MaxContiguousSecurity,
		Duration:              duration,
	}
}
