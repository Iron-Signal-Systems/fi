//go:build fi_security_coverage_bulk_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/jackc/pgx/v5"
)

// TestSecurityCoverageBulkPostgreSQL verifies generated source IDs, exact
// policy-kind/root relationships, bounded flushes and transaction rollback.
// The connection is rejected unless it belongs to an isolated local cluster.
func TestSecurityCoverageBulkPostgreSQL(t *testing.T) {
	dsn := os.Getenv("FI_SECURITY_COVERAGE_BULK_TEST_DSN")
	expected := os.Getenv("FI_SECURITY_COVERAGE_BULK_TEST_DATA")
	if dsn == "" || expected == "" {
		t.Fatal("isolated PostgreSQL DSN and data directory required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())

	var directory, listener string
	if err := conn.QueryRow(ctx, `SELECT current_setting('data_directory'), current_setting('listen_addresses')`).Scan(&directory, &listener); err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(directory) != filepath.Clean(expected) || listener != "" {
		t.Fatalf("STOP: unexpected PostgreSQL server: data=%q listener=%q", directory, listener)
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())

	ddl := []string{
		`CREATE SCHEMA fi`,
		`CREATE TABLE fi.source_record (
 source_record_id bigint GENERATED ALWAYS AS IDENTITY
 (START WITH 101 INCREMENT BY 7) PRIMARY KEY,
 source_batch_id bigint NOT NULL,
 record_ordinal bigint NOT NULL,
 UNIQUE(source_batch_id,record_ordinal))`,
		`CREATE TABLE fi.windows_security_coverage (
 source_record_id bigint PRIMARY KEY REFERENCES fi.source_record,
 observed_at timestamptz NOT NULL,
 collection_method text NOT NULL,
 security_log_readable boolean NOT NULL,
 status text NOT NULL CHECK (status IN ('Ready','Partial')))`,
		`CREATE TABLE fi.windows_security_audit_policy (
 source_record_id bigint NOT NULL REFERENCES fi.windows_security_coverage,
 policy_kind text NOT NULL CHECK (policy_kind IN ('FileSystem','HandleManipulation','DetailedFileShare','AuditPolicyChange')),
 subcategory_guid text NOT NULL,
 auditing_information text NOT NULL,
 success_enabled boolean NOT NULL,
 failure_enabled boolean NOT NULL,
 reason_code text,
 PRIMARY KEY (source_record_id,policy_kind))`,
		`CREATE TABLE fi.windows_security_root_coverage (
 source_record_id bigint NOT NULL REFERENCES fi.windows_security_coverage,
 root_ordinal integer NOT NULL CHECK(root_ordinal>0),
 scope_id text NOT NULL,
 governed_root text NOT NULL,
 sacl_state text NOT NULL,
 recommended_change_audit_present boolean NOT NULL,
 recommended_read_audit_present boolean NOT NULL,
 reason_code text,
 PRIMARY KEY(source_record_id,root_ordinal),
 UNIQUE(source_record_id,scope_id))`,
	}
	for _, statement := range ddl {
		if _, err := tx.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}

	profile := &ingestStageProfile{}
	state := newSecurityCoverageBulkState(profile)
	observedAt := time.Now().UTC().Format(time.RFC3339Nano)
	policy := records.WindowsSecurityAuditPolicyObservation{
		SubcategoryGUID:     "{11111111-1111-1111-1111-111111111111}",
		AuditingInformation: "Success and Failure", SuccessEnabled: true,
	}
	value := records.WindowsSecurityCoverageObservation{
		ObservedAt:          observedAt,
		CollectionMethod:    records.WindowsSecurityCollectionMethod,
		SecurityLogReadable: true,
		FileSystemPolicy:    policy, HandleManipulationPolicy: policy,
		DetailedFileSharePolicy: policy, AuditPolicyChangePolicy: policy,
		Status: records.WindowsSecurityCoverageReady,
	}

	var firstID int64
	const total = securityCoverageBulkMaxRecords + 1
	for i := 0; i < total; i++ {
		// Each record can originate from a distinct immutable source batch.
		var sourceRecordID int64
		if err := tx.QueryRow(ctx, `INSERT INTO fi.source_record (source_batch_id, record_ordinal)
VALUES ($1,1) RETURNING source_record_id`, i+1).Scan(&sourceRecordID); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstID = sourceRecordID
		}
		current := value
		if i%2 == 1 {
			current.SecurityLogReadable = false
			current.Status = records.WindowsSecurityCoveragePartial
			current.Roots = []records.WindowsSecurityRootAuditCoverage{
				{ScopeID: "root-a", GovernedRoot: `C:\FI`, SACLState: "Present", RecommendedChangeAuditPresent: true},
				{ScopeID: "root-b", GovernedRoot: `D:\FI`, SACLState: "Error", ReasonCode: "NotKnown"},
			}
		}
		payload, err := json.Marshal(current)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(spool.Record{
			Version:    SpoolRecordVersion,
			RecordKind: "WindowsSecurityCoverage",
			ScopeID:    "root-a",
			WrittenAt:  observedAt,
			Payload:    payload,
		})
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := PrepareSourceRecord(append(raw, '\n'))
		if err != nil {
			t.Fatal(err)
		}
		if err := state.add(ctx, tx, sourceRecordID, prepared); err != nil {
			t.Fatal(err)
		}
	}
	if err := state.flush(ctx, tx); err != nil {
		t.Fatal(err)
	}

	if profile.CoverageBulk.Chunks != 2 || profile.CoverageBulk.Records != total ||
		profile.CoverageBulk.Policies != 4*total ||
		profile.CoverageBulk.Roots != 2*(total/2) {
		t.Fatalf("incorrect COPY counters: %+v", profile.CoverageBulk)
	}

	var sourceRows, coverageRows, policyRows, rootRows, invalidPolicies, invalidRoots int64
	if err := tx.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM fi.source_record),
 (SELECT count(*) FROM fi.windows_security_coverage),
 (SELECT count(*) FROM fi.windows_security_audit_policy),
 (SELECT count(*) FROM fi.windows_security_root_coverage),
 (SELECT count(*) FROM fi.windows_security_audit_policy WHERE policy_kind NOT IN
 ('FileSystem','HandleManipulation','DetailedFileShare','AuditPolicyChange')),
 (SELECT count(*) FROM fi.windows_security_root_coverage WHERE root_ordinal NOT IN (1,2))`).Scan(
		&sourceRows, &coverageRows, &policyRows, &rootRows, &invalidPolicies, &invalidRoots,
	); err != nil {
		t.Fatal(err)
	}
	if sourceRows != total || coverageRows != total || policyRows != 4*total ||
		rootRows != 2*(total/2) || invalidPolicies != 0 || invalidRoots != 0 {
		t.Fatalf("row integrity failed: source=%d coverage=%d policies=%d roots=%d bad=%d/%d",
			sourceRows, coverageRows, policyRows, rootRows, invalidPolicies, invalidRoots)
	}

	// Source identities are intentionally nonconsecutive. Check one-to-one
	// associations, policy kinds and root ordinals using actual database rows.
	var firstRoots, secondRoots, distinctKinds, partialUnreadable int64
	if err := tx.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM fi.windows_security_root_coverage WHERE source_record_id=$1),
 (SELECT count(*) FROM fi.windows_security_root_coverage WHERE source_record_id=$2 AND root_ordinal IN (1,2)),
 (SELECT count(DISTINCT policy_kind) FROM fi.windows_security_audit_policy WHERE source_record_id=$1),
 (SELECT count(*) FROM fi.windows_security_coverage WHERE status='Partial' AND NOT security_log_readable)`,
		firstID, firstID+7).Scan(&firstRoots, &secondRoots, &distinctKinds, &partialUnreadable); err != nil {
		t.Fatal(err)
	}
	if firstRoots != 0 || secondRoots != 2 || distinctKinds != 4 || partialUnreadable != total/2 {
		t.Fatalf("source association mismatch: first roots=%d second roots=%d policies=%d partial=%d",
			firstRoots, secondRoots, distinctKinds, partialUnreadable)
	}

	// A second projection of the same source ID must be rejected. The entire
	// surrounding generation transaction is then rolled back.
	state.pending = append(state.pending, securityCoverageBulkRecord{
		sourceRecordID: firstID, observedAt: time.Now(), value: value,
	})
	if err := state.flush(ctx, tx); err == nil {
		t.Fatal("duplicate source-record projection unexpectedly accepted")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	var absent bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('fi.windows_security_coverage') IS NULL`).Scan(&absent); err != nil {
		t.Fatal(err)
	}
	if !absent {
		t.Fatal("rollback did not remove isolated FI schema")
	}
	t.Log("PASS: two bounded COPY flushes, generated IDs, exact policy/root counts, duplicate rejection and rollback")
}
