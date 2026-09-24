// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build linux

package recordingest

import (
	"context"
	"crypto/sha256"
	"fmt"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
)

func projectWindowsSecurityCoverage(ctx context.Context, tx pgx.Tx, sourceRecordID int64, value records.WindowsSecurityCoverageObservation) error {
	observedAt, err := parseRFC3339(value.ObservedAt, "windows_security_coverage.observed_at")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO fi.windows_security_coverage (source_record_id,observed_at,collection_method,security_log_readable,status)
VALUES ($1,$2,$3,$4,$5)
`, sourceRecordID, observedAt, value.CollectionMethod, value.SecurityLogReadable, string(value.Status))
	if err != nil {
		return fmt.Errorf("insert FI Windows Security coverage: %w", err)
	}

	policies := []struct {
		kind  string
		value records.WindowsSecurityAuditPolicyObservation
	}{
		{"FileSystem", value.FileSystemPolicy},
		{"HandleManipulation", value.HandleManipulationPolicy},
		{"DetailedFileShare", value.DetailedFileSharePolicy},
		{"AuditPolicyChange", value.AuditPolicyChangePolicy},
	}
	for _, item := range policies {
		policy := item.value
		_, err := tx.Exec(ctx, `
INSERT INTO fi.windows_security_audit_policy (
 source_record_id,policy_kind,subcategory_guid,auditing_information,success_enabled,failure_enabled,reason_code
) VALUES ($1,$2,$3,$4,$5,$6,$7)
`, sourceRecordID, item.kind, policy.SubcategoryGUID, policy.AuditingInformation, policy.SuccessEnabled, policy.FailureEnabled, nullString(policy.ReasonCode))
		if err != nil {
			return fmt.Errorf("insert FI Windows Security audit policy: %w", err)
		}
	}

	for i, root := range value.Roots {
		_, err := tx.Exec(ctx, `
INSERT INTO fi.windows_security_root_coverage (
 source_record_id,root_ordinal,scope_id,governed_root,sacl_state,recommended_change_audit_present,recommended_read_audit_present,reason_code
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
`, sourceRecordID, i+1, root.ScopeID, root.GovernedRoot, root.SACLState, root.RecommendedChangeAuditPresent, root.RecommendedReadAuditPresent, nullString(root.ReasonCode))
		if err != nil {
			return fmt.Errorf("insert FI Windows Security root coverage: %w", err)
		}
	}
	return nil
}

func projectWindowsSecurityContinuityGap(ctx context.Context, tx pgx.Tx, sourceRecordID int64, value records.WindowsSecurityContinuityGapObservation) error {
	observedAt, err := parseRFC3339(value.ObservedAt, "windows_security_continuity_gap.observed_at")
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO fi.windows_security_continuity_gap (
 source_record_id,observed_at,collection_method,channel,scope_id,reason_code,checkpoint_event_record_id,
 current_oldest_event_record_id,current_newest_event_record_id,coverage_state,reconciliation_action
) VALUES ($1,$2,$3,$4,$5,$6,$7::text::numeric,$8::text::numeric,$9::text::numeric,$10,$11)
`, sourceRecordID, observedAt, value.CollectionMethod, value.Channel, value.ScopeID, value.ReasonCode, value.CheckpointEventRecordID,
		value.CurrentOldestEventRecordID, value.CurrentNewestEventRecordID, value.CoverageState, value.ReconciliationAction)
	if err != nil {
		return fmt.Errorf("insert FI Windows Security continuity gap: %w", err)
	}
	return nil
}

func projectWindowsSecurityEvent(ctx context.Context, tx pgx.Tx, sourceRecordID int64, value records.WindowsSecurityEventObservation) error {
	observedAt, err := parseRFC3339(value.ObservedAt, "windows_security_event.observed_at")
	if err != nil {
		return err
	}
	timeCreated, err := parseRFC3339(value.TimeCreated, "windows_security_event.time_created")
	if err != nil {
		return err
	}
	eventID, err := parseUint(value.EventID, 63, "windows_security_event.event_id")
	if err != nil {
		return err
	}
	rawXML := []byte(value.RawXML)
	digest := sha256.Sum256(rawXML)

	_, err = tx.Exec(ctx, `
INSERT INTO fi.windows_security_event (
 source_record_id,observed_at,collection_method,channel,provider,event_id,version,event_record_id,time_created,computer,keywords,
 audit_result,scope_basis,subject_user_sid,subject_user_name,subject_domain_name,subject_logon_id,object_server,object_type,object_name,
 handle_id,process_id,process_name,access_mask,access_list,access_reason,transaction_id,file_name,link_name,source_ip,source_port,
 share_name,share_local_path,relative_target_name,old_security_descriptor,new_security_descriptor,subcategory_guid,audit_policy_changes,
 raw_xml_bytes,raw_xml_sha256
) VALUES (
 $1,$2,$3,$4,$5,$6,$7,$8::text::numeric,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
 $21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,$39,$40
)
`, sourceRecordID, observedAt, value.CollectionMethod, value.Channel, value.Provider, int64(eventID), nullString(value.Version), value.EventRecordID,
		timeCreated, value.Computer, nullString(value.Keywords), string(value.AuditResult), string(value.ScopeBasis), nullString(value.SubjectUserSID),
		nullString(value.SubjectUserName), nullString(value.SubjectDomainName), nullString(value.SubjectLogonID), nullString(value.ObjectServer),
		nullString(value.ObjectType), nullString(value.ObjectName), nullString(value.HandleID), nullString(value.ProcessID), nullString(value.ProcessName),
		nullString(value.AccessMask), nullString(value.AccessList), nullString(value.AccessReason), nullString(value.TransactionID), nullString(value.FileName),
		nullString(value.LinkName), nullString(value.SourceIP), nullString(value.SourcePort), nullString(value.ShareName), nullString(value.ShareLocalPath),
		nullString(value.RelativeTargetName), nullString(value.OldSecurityDescriptor), nullString(value.NewSecurityDescriptor), nullString(value.SubcategoryGUID),
		nullString(value.AuditPolicyChanges), len(rawXML), digest[:])
	if err != nil {
		return fmt.Errorf("insert FI Windows Security event: %w", err)
	}

	for i, scope := range value.MatchedScopes {
		if _, err := tx.Exec(ctx, `INSERT INTO fi.windows_security_event_scope (source_record_id,scope_ordinal,scope_id,governed_root) VALUES ($1,$2,$3,$4)`, sourceRecordID, i+1, scope.ScopeID, scope.GovernedRoot); err != nil {
			return fmt.Errorf("insert FI Windows Security matched scope: %w", err)
		}
	}
	for i, field := range value.Fields {
		if _, err := tx.Exec(ctx, `INSERT INTO fi.windows_security_event_field (source_record_id,field_ordinal,name,value) VALUES ($1,$2,$3,$4)`, sourceRecordID, i+1, field.Name, field.Value); err != nil {
			return fmt.Errorf("insert FI Windows Security field: %w", err)
		}
	}
	return nil
}
