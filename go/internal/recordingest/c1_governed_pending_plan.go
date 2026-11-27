//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 governed pending schema PLAN ONLY. It never connects to PostgreSQL,
// changes the installed fi schema, or grants live-ingestion admission.
package recordingest

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Iron-Signal-Systems/fi/go/internal/freebsd/backendinstall"
)

// C1GovernedPendingStatement describes a transaction-owned migration step.
type C1GovernedPendingStatement struct {
	Name string
	SQL  string
}

// This control ledger is NOT an acceptance journal. Only the canonical fi
// transaction can write Accepted. No C1 SQL worker can forge verifier B state.
// Pending metadata is tied by FK to the complete signed generation identity.
const c1PendingControlDDL = `
ALTER TABLE fi_c1_pending.recorded_generation
    ADD CONSTRAINT c1_pending_exact_signed_identity_uq UNIQUE
        (source_id, generation_id, receipt_sha256, transfer_sha256,
         record_count, batch_count);
CREATE TABLE fi_c1_pending.generation_control (
    source_id text NOT NULL,
    generation_id text NOT NULL,
    receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256) = 32),
    transfer_sha256 bytea NOT NULL CHECK (octet_length(transfer_sha256) = 32),
    record_count bigint NOT NULL CHECK (record_count > 0),
    batch_count bigint NOT NULL CHECK (batch_count > 0),
    state text NOT NULL DEFAULT 'Pending' CHECK (state IN
        ('Pending', 'SQLSealed', 'BVerified', 'PublicationUncertain', 'Retired')),
    verifier_b_receipt_sha256 bytea CHECK (
        verifier_b_receipt_sha256 IS NULL OR
        octet_length(verifier_b_receipt_sha256) = 32),
    verifier_b_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (source_id, generation_id),
    FOREIGN KEY (source_id, generation_id, receipt_sha256, transfer_sha256,
                 record_count, batch_count)
        REFERENCES fi_c1_pending.recorded_generation
            (source_id, generation_id, receipt_sha256, transfer_sha256,
             record_count, batch_count),
    CHECK ((verifier_b_at IS NULL AND verifier_b_receipt_sha256 IS NULL) OR
           (verifier_b_at IS NOT NULL AND verifier_b_receipt_sha256 IS NOT NULL
            AND verifier_b_receipt_sha256 = receipt_sha256)),
    CHECK (state NOT IN ('BVerified', 'PublicationUncertain', 'Retired') OR
           verifier_b_at IS NOT NULL)
);
CREATE UNIQUE INDEX fi_c1_pending_one_unretired_generation
    ON fi_c1_pending.generation_control ((true))
    WHERE state <> 'Retired';
-- The mirrored journal is never an authority and workers cannot forge B.
REVOKE ALL ON fi_c1_pending.ingest_journal FROM fi_ingest;
-- fi-sor must prove that the untrusted pending journal is EMPTY; SELECT
-- is necessary for read-only admission/replay checks, never acceptance.
GRANT SELECT ON fi_c1_pending.ingest_journal TO fi_ingest;
REVOKE ALL ON fi_c1_pending.generation_control FROM fi_ingest;
GRANT SELECT ON fi_c1_pending.generation_control TO fi_ingest;
-- fi_ingest may admit ONLY an exact signed Pending identity in the SAME
-- metadata transaction. It cannot insert state, verifier fields or proof.
GRANT INSERT (source_id, generation_id, receipt_sha256, transfer_sha256,
              record_count, batch_count)
    ON fi_c1_pending.generation_control TO fi_ingest;
`

// C1GovernedPendingPlan constructs an additive, checksum-pinned SQL plan.
// Unlike the discarded experimental fi_recovery schemas this namespace is
// intended for an audited durable lifecycle inside the existing SoR server.
// Installation, replay, publication and service activation are separate gates.
func C1GovernedPendingPlan() ([]C1GovernedPendingStatement, error) {
	originals, err := backendinstall.C1CanonicalSchemaMigrations()
	if err != nil {
		return nil, err
	}
	if len(originals) != 5 {
		return nil, errors.New("C1 pending: canonical migration count drift")
	}
	plan := make([]C1GovernedPendingStatement, 0, 6)
	for _, src := range originals {
		ddl, err := RewritePrivateProjectionMigration(src.Name, src.SQL)
		if err != nil {
			return nil, fmt.Errorf("C1 pending: canonical source %s: %w", src.Name, err)
		}
		ddl = strings.ReplaceAll(ddl, privateProjectionSchema, c1GovernedPendingSchema)
		if src.Name == "0004_security_field_name_index.sql" {
			old := "DROP INDEX CONCURRENTLY " + c1GovernedPendingSchema + ".windows_security_event_field_name_idx;"
			if strings.Count(ddl, old) != 1 {
				return nil, errors.New("C1 pending: unaudited Security index migration")
			}
			ddl = strings.Replace(ddl, old,
				"DROP INDEX "+c1GovernedPendingSchema+".windows_security_event_field_name_idx;", 1)
		}
		ddl, err = c1MigrationWithoutTransactionEnvelope(ddl)
		if err != nil {
			return nil, err
		}
		if strings.Contains(ddl, "fi_recovery") || strings.Contains(ddl, "fi.") ||
			strings.Contains(ddl, "DROP TABLE") || strings.Contains(ddl, "DROP SCHEMA") ||
			strings.Contains(ddl, "DROP INDEX CONCURRENTLY") ||
			strings.Contains(ddl, "CREATE TABLE fi.") {
			return nil, fmt.Errorf("C1 pending: unsafe or discarded-schema SQL in %s", src.Name)
		}
		plan = append(plan, C1GovernedPendingStatement{Name: src.Name, SQL: ddl})
	}
	if !strings.Contains(plan[0].SQL,
		"CREATE SCHEMA "+c1GovernedPendingSchema+" AUTHORIZATION fi_owner;") {
		return nil, errors.New("C1 pending: missing isolated schema creation")
	}
	plan = append(plan, C1GovernedPendingStatement{
		Name: "c1_governed_pending_control", SQL: c1PendingControlDDL,
	})
	return plan, nil
}
