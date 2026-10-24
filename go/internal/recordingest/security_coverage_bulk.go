// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/jackc/pgx/v5"
)

const (
	securityCoverageBulkMaxBytes   = 8 << 20
	securityCoverageBulkMaxRecords = 512
)

// securityCoverageBulkProfile reports projection work across source batches.
// The total is included in ingestStageProfile.Projection, not SourceSQL.
type securityCoverageBulkProfile struct {
	Chunks   int64
	Policies int64
	Records  int64
	Roots    int64

	Prepare time.Duration
	Copy    time.Duration
}

type securityCoverageBulkRecord struct {
	sourceRecordID int64
	observedAt     time.Time
	value          records.WindowsSecurityCoverageObservation
}

// securityCoverageBulkState holds bounded, validated projections. Source rows
// have already been inserted in original custody order. In particular, this
// state must never defer allocating source_record_id values: the USN capture
// validator depends on source-record ordering across batches.
type securityCoverageBulkState struct {
	bytes   int64
	pending []securityCoverageBulkRecord
	profile *ingestStageProfile
}

func newSecurityCoverageBulkState(profile *ingestStageProfile) *securityCoverageBulkState {
	return &securityCoverageBulkState{profile: profile}
}

// add validates the exact decoded payload before retaining it. A single
// oversized record is allowed, because input size is already bounded by the
// signed batch contract; it is flushed immediately rather than accumulated.
func (state *securityCoverageBulkState) add(
	ctx context.Context,
	tx pgx.Tx,
	sourceRecordID int64,
	prepared SourceRecord,
) error {
	if state == nil || state.profile == nil || sourceRecordID <= 0 ||
		prepared.Record.RecordKind != "WindowsSecurityCoverage" || prepared.RecordBytes <= 0 {
		return errors.New("FI Security coverage bulk inputs are incomplete")
	}

	started := time.Now()
	var value records.WindowsSecurityCoverageObservation
	if err := decodeStrictPayload(prepared.Record.Payload, &value); err != nil {
		return projectionDecodeError(prepared.Record.RecordKind, err)
	}
	if err := records.ValidateWindowsSecurityCoverageObservation(value); err != nil {
		return projectionValidationError(prepared.Record.RecordKind, err)
	}
	observedAt, err := parseRFC3339(value.ObservedAt, "windows_security_coverage.observed_at")
	if err != nil {
		return err
	}
	elapsed := time.Since(started)
	state.profile.CoverageBulk.Prepare += elapsed
	state.profile.Projection += elapsed

	if len(state.pending) >= securityCoverageBulkMaxRecords ||
		(len(state.pending) > 0 && state.bytes+int64(prepared.RecordBytes) > securityCoverageBulkMaxBytes) {
		if err := state.flush(ctx, tx); err != nil {
			return err
		}
	}

	state.pending = append(state.pending, securityCoverageBulkRecord{
		sourceRecordID: sourceRecordID,
		observedAt:     observedAt,
		value:          value,
	})
	state.bytes += int64(prepared.RecordBytes)

	if state.bytes > securityCoverageBulkMaxBytes {
		return state.flush(ctx, tx)
	}
	return nil
}

// flush publishes coverage, four exact audit-policy rows per observation,
// and every governed-root row in dependency order. The generation transaction
// owns atomicity; any COPY error causes the caller to reject and roll back.
func (state *securityCoverageBulkState) flush(ctx context.Context, tx pgx.Tx) error {
	if state == nil || state.profile == nil {
		return errors.New("FI Security coverage bulk state is absent")
	}
	if len(state.pending) == 0 {
		return nil
	}
	if tx == nil {
		return errors.New("FI Security coverage bulk transaction is absent")
	}

	started := time.Now()
	defer func() {
		elapsed := time.Since(started)
		state.profile.CoverageBulk.Copy += elapsed
		state.profile.Projection += elapsed
	}()

	coverageColumns := []string{
		"source_record_id", "observed_at", "collection_method", "security_log_readable", "status",
	}
	copied, err := tx.CopyFrom(ctx, pgx.Identifier{"fi", "windows_security_coverage"}, coverageColumns,
		pgx.CopyFromSlice(len(state.pending), func(i int) ([]any, error) {
			item := state.pending[i]
			return []any{
				item.sourceRecordID, item.observedAt, item.value.CollectionMethod,
				item.value.SecurityLogReadable, string(item.value.Status),
			}, nil
		}))
	if err != nil {
		return fmt.Errorf("FI Security coverage COPY: %w", err)
	}
	if copied != int64(len(state.pending)) {
		return fmt.Errorf("FI Security coverage COPY rows: got %d expected %d", copied, len(state.pending))
	}

	// The original projector used this exact policy-to-kind mapping.
	policyRows := make([][]any, 0, 4*len(state.pending))
	rootCount := 0
	for _, item := range state.pending {
		rootCount += len(item.value.Roots)
		policies := []struct {
			kind  string
			value records.WindowsSecurityAuditPolicyObservation
		}{
			{"FileSystem", item.value.FileSystemPolicy},
			{"HandleManipulation", item.value.HandleManipulationPolicy},
			{"DetailedFileShare", item.value.DetailedFileSharePolicy},
			{"AuditPolicyChange", item.value.AuditPolicyChangePolicy},
		}
		for _, policy := range policies {
			policyRows = append(policyRows, []any{
				item.sourceRecordID, policy.kind, policy.value.SubcategoryGUID,
				policy.value.AuditingInformation, policy.value.SuccessEnabled,
				policy.value.FailureEnabled, nullString(policy.value.ReasonCode),
			})
		}
	}

	policyColumns := []string{
		"source_record_id", "policy_kind", "subcategory_guid", "auditing_information",
		"success_enabled", "failure_enabled", "reason_code",
	}
	copied, err = tx.CopyFrom(ctx, pgx.Identifier{"fi", "windows_security_audit_policy"}, policyColumns,
		pgx.CopyFromSlice(len(policyRows), func(i int) ([]any, error) {
			return policyRows[i], nil
		}))
	if err != nil {
		return fmt.Errorf("FI Security coverage audit-policy COPY: %w", err)
	}
	if copied != int64(len(policyRows)) {
		return fmt.Errorf("FI Security coverage audit-policy COPY rows: got %d expected %d", copied, len(policyRows))
	}

	if rootCount > 0 {
		rootRows := make([][]any, 0, rootCount)
		for _, item := range state.pending {
			for i, root := range item.value.Roots {
				rootRows = append(rootRows, []any{
					item.sourceRecordID, i + 1, root.ScopeID, root.GovernedRoot,
					root.SACLState, root.RecommendedChangeAuditPresent,
					root.RecommendedReadAuditPresent, nullString(root.ReasonCode),
				})
			}
		}
		rootColumns := []string{
			"source_record_id", "root_ordinal", "scope_id", "governed_root",
			"sacl_state", "recommended_change_audit_present",
			"recommended_read_audit_present", "reason_code",
		}
		copied, err = tx.CopyFrom(ctx, pgx.Identifier{"fi", "windows_security_root_coverage"}, rootColumns,
			pgx.CopyFromSlice(len(rootRows), func(i int) ([]any, error) {
				return rootRows[i], nil
			}))
		if err != nil {
			return fmt.Errorf("FI Security coverage governed-root COPY: %w", err)
		}
		if copied != int64(len(rootRows)) {
			return fmt.Errorf("FI Security coverage governed-root COPY rows: got %d expected %d", copied, len(rootRows))
		}
	}

	state.profile.CoverageBulk.Chunks++
	state.profile.CoverageBulk.Policies += int64(len(policyRows))
	state.profile.CoverageBulk.Records += int64(len(state.pending))
	state.profile.CoverageBulk.Roots += int64(rootCount)
	state.pending = nil
	state.bytes = 0
	return nil
}
