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
	Batches int64
	Events  int64
	Scopes  int64
	Fields  int64

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
}

type securityBulkRecord struct {
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
	if len(pending) > securityBulkMaxRecords {
		return errors.New("FI Security bulk chunk exceeds record limit")
	}

	sqlStarted := time.Now()
	sourceColumns := []string{"source_batch_id", "record_ordinal", "version", "record_kind", "scope_id", "written_at", "record_bytes", "record_sha256", "ingest_version"}
	sourceCopyStarted := time.Now()
	copied, err := tx.CopyFrom(ctx, pgx.Identifier{"fi", "source_record"}, sourceColumns,
		pgx.CopyFromSlice(len(pending), func(i int) ([]any, error) {
			p := pending[i]
			return []any{sourceBatchID, p.ordinal, p.prepared.Record.Version, p.prepared.Record.RecordKind, p.prepared.Record.ScopeID, p.prepared.WrittenAtUTC, p.prepared.RecordBytes, p.digest, IngestVersion}, nil
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
	rows, err := tx.Query(ctx, `SELECT record_ordinal,source_record_id FROM fi.source_record WHERE source_batch_id=$1 AND record_ordinal BETWEEN $2 AND $3 ORDER BY record_ordinal`, sourceBatchID, pending[0].ordinal, pending[len(pending)-1].ordinal)
	if err != nil {
		return fmt.Errorf("FI Security bulk source ID lookup: %w", err)
	}
	index := 0
	for rows.Next() {
		var ordinal, id int64
		if err := rows.Scan(&ordinal, &id); err != nil {
			rows.Close()
			return fmt.Errorf("FI Security bulk source ID scan: %w", err)
		}
		if index >= len(pending) || ordinal != pending[index].ordinal || id <= 0 {
			rows.Close()
			return fmt.Errorf("FI Security bulk source identity mismatch at index %d", index)
		}
		pending[index].sourceRecordID = id
		index++
	}
	queryErr := rows.Err()
	rows.Close()
	if queryErr != nil {
		return fmt.Errorf("FI Security bulk source ID read: %w", queryErr)
	}
	if index != len(pending) {
		return fmt.Errorf("FI Security bulk source IDs: got %d expected %d", index, len(pending))
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
	eventCopyStarted := time.Now()
	copied, err = tx.CopyFrom(ctx, pgx.Identifier{"fi", "windows_security_event"}, eventColumns,
		pgx.CopyFromSlice(len(pending), func(i int) ([]any, error) {
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
		}))
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
			cursor: cursor, maxRows: securityFieldCopyMaxRows, maxBytes: securityFieldCopyMaxBytes,
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
	profile.Projection += time.Since(projectionStarted)
	return nil
}
