// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	securityBulkMaxRecords = 1024
	securityBulkMaxBytes   = 8 << 20
)

type securityBulkTimingCounters struct {
	Batches               int64
	Events                int64
	Scopes                int64
	Fields                int64
	SourceBytes           int64
	MaxContiguousSecurity int

	Prepare      time.Duration
	SourceCopy   time.Duration
	IDLookup     time.Duration
	EventCopy    time.Duration
	ChildPrepare time.Duration
	ScopeCopy    time.Duration
	FieldCopy    time.Duration

	// Per-COPY distributions supplement (not replace) existing aggregate timers.
	SourceLatency copyCallLatency
	EventLatency  copyCallLatency
	ScopeLatency  copyCallLatency
	FieldLatency  copyCallLatency

	// Only populated in the isolated private W128/P3 trial. This records
	// WHY the existing Security COPY boundary occurred, not a new boundary.
	PrivateFlush securityBulkFlushProfile
}

// securityBulkFlushReason is recorded only AFTER the corresponding source,
// event and child COPY operations have succeeded. No per-record logging or
// changes to the source-ordering, size limits, or transaction are permitted.
type securityBulkFlushReason uint8

const (
	securityFlushRecordLimit securityBulkFlushReason = iota + 1
	securityFlushByteLimit
	securityFlushBothLimits
	securityFlushCoverage
	securityFlushOtherKind
	securityFlushChunkEnd
	securityFlushBatchEnd
)

type securityBulkFlushProfile struct {
	Calls          int64
	Events         int64
	SourceBytes    int64
	MinEvents      int
	MaxEvents      int
	MinSourceBytes int64
	MaxSourceBytes int64

	RecordLimit int64
	ByteLimit   int64
	BothLimits  int64
	Coverage    int64
	OtherKind   int64
	ChunkEnd    int64
	BatchEnd    int64
}

// note is strictly observational: byte counts represent original signed
// source-record bytes, NOT in-memory row allocations, COPY wire bytes or WAL.
func (p *securityBulkFlushProfile) note(reason securityBulkFlushReason, events int, sourceBytes int64) {
	if events <= 0 {
		return // A call with no pending Security records performs no COPY.
	}
	if p.Calls == 0 || events < p.MinEvents {
		p.MinEvents = events
	}
	if events > p.MaxEvents {
		p.MaxEvents = events
	}
	if p.Calls == 0 || sourceBytes < p.MinSourceBytes {
		p.MinSourceBytes = sourceBytes
	}
	if sourceBytes > p.MaxSourceBytes {
		p.MaxSourceBytes = sourceBytes
	}
	p.Calls++
	p.Events += int64(events)
	p.SourceBytes += sourceBytes
	switch reason {
	case securityFlushRecordLimit:
		p.RecordLimit++
	case securityFlushByteLimit:
		p.ByteLimit++
	case securityFlushBothLimits:
		p.BothLimits++
	case securityFlushCoverage:
		p.Coverage++
	case securityFlushOtherKind:
		p.OtherKind++
	case securityFlushChunkEnd:
		p.ChunkEnd++
	case securityFlushBatchEnd:
		p.BatchEnd++
	}
}

// limitReason classifies an EXISTING P3 flush; it must not determine whether
// a flush happens. The original securityBulkLimits.shouldFlushBefore remains
// the sole limit check in the ingest loop.
func (limits securityBulkLimits) limitReason(count int, bufferedBytes, nextBytes int64) securityBulkFlushReason {
	byCount := count >= limits.MaxRecords
	byBytes := count > 0 && nextBytes > limits.MaxBytes-bufferedBytes
	switch {
	case byCount && byBytes:
		return securityFlushBothLimits
	case byCount:
		return securityFlushRecordLimit
	default:
		return securityFlushByteLimit
	}
}

func (p securityBulkFlushProfile) summary() string {
	var meanEvents, meanBytes float64
	if p.Calls > 0 {
		meanEvents = float64(p.Events) / float64(p.Calls)
		meanBytes = float64(p.SourceBytes) / float64(p.Calls)
	}
	return fmt.Sprintf("calls=%d events=%d source_bytes=%d avg_events=%.1f min_events=%d max_events=%d avg_source_bytes=%.0f min_source_bytes=%d max_source_bytes=%d record_limit=%d byte_limit=%d both_limits=%d coverage=%d other_kind=%d chunk_end=%d batch_end=%d",
		p.Calls, p.Events, p.SourceBytes, meanEvents, p.MinEvents, p.MaxEvents,
		meanBytes, p.MinSourceBytes, p.MaxSourceBytes, p.RecordLimit,
		p.ByteLimit, p.BothLimits, p.Coverage, p.OtherKind, p.ChunkEnd, p.BatchEnd)
}

type securityBulkRecord struct {
	sourceBatchID  int64 // original signed batch, not a processing-chunk identifier
	ordinal        int64
	prepared       SourceRecord
	digest         []byte
	value          records.WindowsSecurityEventObservation
	observedAt     time.Time
	timeCreated    time.Time
	eventID        int64
	eventRecordID  pgtype.Numeric
	sourceRecordID int64
}

func prepareSecurityBulkRecord(ordinal int64, prepared SourceRecord, digest []byte) (securityBulkRecord, error) {
	if prepared.Record.RecordKind != "WindowsSecurityEvent" {
		return securityBulkRecord{}, errors.New("FI Security bulk record kind mismatch")
	}
	var value records.WindowsSecurityEventObservation
	if err := decodeStrictPayload(prepared.Record.Payload, &value); err != nil {
		return securityBulkRecord{}, projectionDecodeError(prepared.Record.RecordKind, err)
	}
	if err := records.ValidateWindowsSecurityEventObservation(value); err != nil {
		return securityBulkRecord{}, projectionValidationError(prepared.Record.RecordKind, err)
	}
	observedAt, err := parseRFC3339(value.ObservedAt, "windows_security_event.observed_at")
	if err != nil {
		return securityBulkRecord{}, err
	}
	timeCreated, err := parseRFC3339(value.TimeCreated, "windows_security_event.time_created")
	if err != nil {
		return securityBulkRecord{}, err
	}
	parsedEventID, err := parseUint(value.EventID, 63, "windows_security_event.event_id")
	if err != nil {
		return securityBulkRecord{}, err
	}
	eventRecordID, ok := new(big.Int).SetString(value.EventRecordID, 10)
	if !ok || eventRecordID.Sign() < 0 {
		return securityBulkRecord{}, errors.New("FI Windows Security event record ID is not an unsigned decimal")
	}
	return securityBulkRecord{
		ordinal: ordinal, prepared: prepared, digest: digest, value: value,
		observedAt: observedAt, timeCreated: timeCreated, eventID: int64(parsedEventID),
		eventRecordID: pgtype.Numeric{Int: eventRecordID, Exp: 0, Valid: true},
	}, nil
}

func copySecurityBulk(ctx context.Context, tx pgx.Tx, sourceBatchID int64, pending []securityBulkRecord, profile *ingestStageProfile) error {
	if len(pending) == 0 {
		return nil
	}
	limits := securityBulkLimitsFromContext(ctx)
	if len(pending) > limits.MaxRecords {
		return fmt.Errorf("FI Security bulk chunk exceeds %s record limit (%d)", limits.Name, limits.MaxRecords)
	}

	sqlStarted := time.Now()
	sourceColumns := []string{"source_batch_id", "record_ordinal", "version", "record_kind", "scope_id", "written_at", "record_bytes", "record_sha256", "ingest_version"}
	sourceCopyStarted := time.Now()
	copied, err := tx.CopyFrom(ctx, pgx.Identifier{"fi", "source_record"}, sourceColumns,
		pgx.CopyFromSlice(len(pending), func(i int) ([]any, error) {
			p := pending[i]
			return []any{bulkSourceBatchID(p.sourceBatchID, sourceBatchID), p.ordinal, p.prepared.Record.Version, p.prepared.Record.RecordKind, p.prepared.Record.ScopeID, p.prepared.WrittenAtUTC, p.prepared.RecordBytes, p.digest, IngestVersion}, nil
		}))
	elapsedSourceCopy := time.Since(sourceCopyStarted)
	profile.SecurityBulk.SourceCopy += elapsedSourceCopy
	profile.SecurityBulk.SourceLatency.observe(elapsedSourceCopy)
	if err != nil {
		return fmt.Errorf("FI Security bulk source COPY: %w", err)
	}
	if copied != int64(len(pending)) {
		return fmt.Errorf("FI Security bulk source COPY count: got %d expected %d", copied, len(pending))
	}

	idLookupStarted := time.Now()
	batchIDs := make([]int64, len(pending))
	ordinals := make([]int64, len(pending))
	for i, p := range pending {
		batchIDs[i] = bulkSourceBatchID(p.sourceBatchID, sourceBatchID)
		ordinals[i] = p.ordinal
	}
	ids, err := lookupBulkSourceRecordIDs(ctx, tx, batchIDs, ordinals)
	if err != nil {
		return fmt.Errorf("FI Security bulk source ID lookup: %w", err)
	}
	for i, id := range ids {
		pending[i].sourceRecordID = id
	}
	profile.SecurityBulk.IDLookup += time.Since(idLookupStarted)
	profile.SourceSQL += time.Since(sqlStarted)

	projectionStarted := time.Now()
	eventColumns := []string{
		"source_record_id", "observed_at", "collection_method", "channel", "provider", "event_id", "version", "event_record_id", "time_created", "computer", "keywords",
		"audit_result", "scope_basis", "subject_user_sid", "subject_user_name", "subject_domain_name", "subject_logon_id", "object_server", "object_type", "object_name",
		"handle_id", "process_id", "process_name", "access_mask", "access_list", "access_reason", "transaction_id", "file_name", "link_name", "source_ip", "source_port",
		"share_name", "share_local_path", "relative_target_name", "old_security_descriptor", "new_security_descriptor", "subcategory_guid", "audit_policy_changes",
		"raw_xml_bytes", "raw_xml_sha256",
	}
	// The established callback remains the default for production and
	// every ordinary P1/P3 operation. The reusable row-buffer candidate
	// is enabled only by an explicit private W128/P3 experiment flag.
	var eventRows pgx.CopyFromSource = pgx.CopyFromSlice(len(pending), func(i int) ([]any, error) {
			p := pending[i]
			v := p.value
			rawXML := []byte(v.RawXML)
			digest := sha256.Sum256(rawXML)
			return []any{
				p.sourceRecordID, p.observedAt, v.CollectionMethod, v.Channel, v.Provider, p.eventID, nullString(v.Version), p.eventRecordID, p.timeCreated, v.Computer, nullString(v.Keywords),
				string(v.AuditResult), string(v.ScopeBasis), nullString(v.SubjectUserSID), nullString(v.SubjectUserName), nullString(v.SubjectDomainName), nullString(v.SubjectLogonID), nullString(v.ObjectServer), nullString(v.ObjectType), nullString(v.ObjectName),
				nullString(v.HandleID), nullString(v.ProcessID), nullString(v.ProcessName), nullString(v.AccessMask), nullString(v.AccessList), nullString(v.AccessReason), nullString(v.TransactionID), nullString(v.FileName), nullString(v.LinkName), nullString(v.SourceIP), nullString(v.SourcePort),
				nullString(v.ShareName), nullString(v.ShareLocalPath), nullString(v.RelativeTargetName), nullString(v.OldSecurityDescriptor), nullString(v.NewSecurityDescriptor), nullString(v.SubcategoryGUID), nullString(v.AuditPolicyChanges), len(rawXML), digest[:],
			}, nil
		})
	if usePrivateSecurityEventCopySource(ctx) {
		eventRows = newSecurityEventCopySource(pending)
	}
	eventCopyStarted := time.Now()
	copied, err = tx.CopyFrom(ctx, pgx.Identifier{"fi", "windows_security_event"}, eventColumns, eventRows)
	elapsedEventCopy := time.Since(eventCopyStarted)
	profile.SecurityBulk.EventCopy += elapsedEventCopy
	profile.SecurityBulk.EventLatency.observe(elapsedEventCopy)
	if err != nil {
		return fmt.Errorf("FI Security bulk event COPY: %w", err)
	}
	if copied != int64(len(pending)) {
		return fmt.Errorf("FI Security bulk event COPY count: got %d expected %d", copied, len(pending))
	}

	childPrepareStarted := time.Now()
	var scopeCount, fieldCount int
	for _, p := range pending {
		scopeCount += len(p.value.MatchedScopes)
		fieldCount += len(p.value.Fields)
	}
	scopes := make([][]any, 0, scopeCount)
	for _, p := range pending {
		for i, s := range p.value.MatchedScopes {
			scopes = append(scopes, []any{p.sourceRecordID, i + 1, s.ScopeID, s.GovernedRoot})
		}
	}
	profile.SecurityBulk.ChildPrepare += time.Since(childPrepareStarted)
	if len(scopes) > 0 {
		scopeCopyStarted := time.Now()
		copied, err = tx.CopyFrom(ctx, pgx.Identifier{"fi", "windows_security_event_scope"}, []string{"source_record_id", "scope_ordinal", "scope_id", "governed_root"},
			pgx.CopyFromSlice(len(scopes), func(i int) ([]any, error) { return scopes[i], nil }))
		elapsedScopeCopy := time.Since(scopeCopyStarted)
		profile.SecurityBulk.ScopeCopy += elapsedScopeCopy
		profile.SecurityBulk.ScopeLatency.observe(elapsedScopeCopy)
		if err != nil {
			return fmt.Errorf("FI Security bulk scopes COPY: %w", err)
		}
		if copied != int64(len(scopes)) {
			return fmt.Errorf("FI Security bulk scopes count: got %d expected %d", copied, len(scopes))
		}
	}
	// Feed fields directly from the already validated event payloads. Do not
	// materialize another [][]any array proportional to event-field expansion.
	cursor := newSecurityFieldCopyCursor(pending)
	var writtenFields int64
	for cursor.hasNext() {
		chunk := &securityFieldCopyChunk{
			cursor: cursor, maxRows: securityFieldCopyRowsForContext(ctx), maxBytes: securityFieldCopyBytesForContext(ctx),
		}
		fieldCopyStarted := time.Now()
		copied, err = tx.CopyFrom(ctx, pgx.Identifier{"fi", "windows_security_event_field"},
			[]string{"source_record_id", "field_ordinal", "name", "value"}, chunk)
		elapsedFieldCopy := time.Since(fieldCopyStarted)
		profile.SecurityBulk.FieldCopy += elapsedFieldCopy
		profile.SecurityBulk.FieldLatency.observe(elapsedFieldCopy)
		if err != nil {
			return fmt.Errorf("FI Security bulk fields streaming COPY: %w", err)
		}
		if chunk.rows == 0 || copied != int64(chunk.rows) {
			return fmt.Errorf("FI Security bulk fields streaming COPY count: got %d expected %d", copied, chunk.rows)
		}
		writtenFields += copied
	}
	if writtenFields != int64(fieldCount) {
		return fmt.Errorf("FI Security bulk fields total: got %d expected %d", writtenFields, fieldCount)
	}
	profile.SecurityBulk.Batches++
	profile.SecurityBulk.Events += int64(len(pending))
	profile.SecurityBulk.Scopes += int64(len(scopes))
	profile.SecurityBulk.Fields += writtenFields
	elapsedProjection := time.Since(projectionStarted)
	profile.Projection += elapsedProjection
	profile.SecurityProjection += elapsedProjection
	return nil
}
