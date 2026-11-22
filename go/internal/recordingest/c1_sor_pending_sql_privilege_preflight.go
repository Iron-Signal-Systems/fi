//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Read-only fi-sor C1 pending schema/ACL preflight. This function does not
// install schemas or grant privileges; missing/damaged metadata blocks START.
package recordingest

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

func c1ReadOnlyGovernedPendingWorkerPrivileges(ctx context.Context, tx pgx.Tx) error {
	if ctx == nil || tx == nil {
		return errors.New("C1 pending: read-only SQL transaction required")
	}
	var role string
	var exists, schemaUse, schemaCreate bool
	if err := tx.QueryRow(ctx, `SELECT current_user,
		to_regnamespace('fi_c1_pending') IS NOT NULL,
		has_schema_privilege(current_user,'fi_c1_pending','USAGE'),
		has_schema_privilege(current_user,'fi_c1_pending','CREATE')`).
		Scan(&role, &exists, &schemaUse, &schemaCreate); err != nil {
		return err
	}
	if role != "fi_ingest" || !exists || !schemaUse || schemaCreate {
		return errors.New("C1 pending: wrong SQL role or governed schema ACL")
	}
	// The ONLY extra relation is generation_control. This prevents a
	// table rename from passing an ACL-only survey on a partial schema.
	var canonical, pending, missing, extra int64
	if err := tx.QueryRow(ctx, `
WITH canonical AS (
 SELECT c.relname,c.relkind FROM pg_class c
 JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='fi' AND c.relkind IN ('r','p')
), pending AS (
 SELECT c.relname,c.relkind FROM pg_class c
 JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='fi_c1_pending' AND c.relkind IN ('r','p')
 AND c.relname <> 'generation_control'
)
SELECT (SELECT count(*) FROM canonical)::bigint,
 (SELECT count(*) FROM pending)::bigint,
 (SELECT count(*) FROM canonical c WHERE NOT EXISTS(
  SELECT 1 FROM pending p WHERE p.relname=c.relname AND p.relkind=c.relkind))::bigint,
 (SELECT count(*) FROM pending p WHERE NOT EXISTS(
  SELECT 1 FROM canonical c WHERE c.relname=p.relname AND c.relkind=p.relkind))::bigint
`).Scan(&canonical, &pending, &missing, &extra); err != nil {
		return err
	}
	if canonical < 40 || pending != canonical || missing != 0 || extra != 0 {
		return fmt.Errorf("C1 pending: incomplete full FI relation mirror canonical=%d pending=%d missing=%d extra=%d",
			canonical, pending, missing, extra)
	}
	var tableDenied, sequenceDenied int64
	if err := tx.QueryRow(ctx, `
SELECT
 count(*) FILTER (WHERE c.relkind IN ('r','p') AND
  c.relname NOT IN ('ingest_journal','generation_control') AND
  NOT (has_table_privilege(current_user,c.oid,'SELECT') AND
       has_table_privilege(current_user,c.oid,'INSERT')))::bigint,
 count(*) FILTER (WHERE c.relkind='S' AND
  NOT (has_sequence_privilege(current_user,c.oid,'USAGE') AND
       has_sequence_privilege(current_user,c.oid,'SELECT')))::bigint
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname='fi_c1_pending'`).Scan(&tableDenied, &sequenceDenied); err != nil {
		return err
	}
	if tableDenied != 0 || sequenceDenied != 0 {
		return errors.New("C1 pending: incomplete SQL worker table/sequence permissions")
	}
	var readControl, insertIdentity, insertState, insertProof, writeControl bool
	var readJournal, writeJournal, updateJournal, deleteJournal, truncateJournal, writeCanonical bool
	if err := tx.QueryRow(ctx, `SELECT
 has_table_privilege(current_user,'fi_c1_pending.generation_control','SELECT'),
 has_column_privilege(current_user,'fi_c1_pending.generation_control','source_id','INSERT'),
 has_column_privilege(current_user,'fi_c1_pending.generation_control','state','INSERT'),
 has_column_privilege(current_user,'fi_c1_pending.generation_control','verifier_b_at','INSERT'),
 has_table_privilege(current_user,'fi_c1_pending.generation_control','UPDATE'),
 has_table_privilege(current_user,'fi_c1_pending.ingest_journal','SELECT'),
 has_table_privilege(current_user,'fi_c1_pending.ingest_journal','INSERT'),
 has_table_privilege(current_user,'fi_c1_pending.ingest_journal','UPDATE'),
 has_table_privilege(current_user,'fi_c1_pending.ingest_journal','DELETE'),
 has_table_privilege(current_user,'fi_c1_pending.ingest_journal','TRUNCATE'),
 has_table_privilege(current_user,'fi.source_record','UPDATE')`).
		Scan(&readControl,&insertIdentity,&insertState,&insertProof,
			&writeControl,&readJournal,&writeJournal,&updateJournal,&deleteJournal,
            &truncateJournal,&writeCanonical); err != nil {
		return err
	}
	if !readControl || !insertIdentity || insertState || insertProof ||
		writeControl || !readJournal || writeJournal || updateJournal ||
        deleteJournal || truncateJournal || writeCanonical {
		return errors.New("C1 pending: writer could forge B, Accepted, or mutate canonical history")
	}
	return nil
}

func c1PreflightLocalGovernedPendingSQL(ctx context.Context, dsn string) error {
	conn, _, err := openC1SoRLocalSQL(ctx, dsn, "")
	if err != nil {
		return err
	}
	defer conn.Close(context.Background())
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if err = c1ReadOnlyGovernedPendingWorkerPrivileges(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
