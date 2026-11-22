//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Transaction-scoped governed pending DDL. No executable installer or
// service activation invokes this function on the populated C220.
// Disposable PostgreSQL 18 CI exercises it under forced SQL rollback.
package recordingest

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// c1InstallGovernedPendingSchemaTx is called with a preflighted ADMIN-owned
// transaction. It never creates a new database, changes canonical fi rows,
// installs the discarded fi_recovery schemas, or grants journal authority.
func c1InstallGovernedPendingSchemaTx(ctx context.Context, tx pgx.Tx) error {
	if ctx == nil || tx == nil {
		return errors.New("C1 pending: owning PostgreSQL transaction required")
	}
	plan, err := C1GovernedPendingPlan()
	if err != nil {
		return err
	}
	for _, step := range plan {
		if _, err = tx.Exec(ctx, step.SQL, pgx.QueryExecModeSimpleProtocol); err != nil {
			return fmt.Errorf("C1 pending: atomic DDL %s: %w", step.Name, err)
		}
	}
	// The actual SQL worker operates inside fi-sor over its local socket.
	// Restrict it to relational reads/inserts, not lifecycle or journal
	// mutation, and do not delegate schema CREATE, UPDATE or DELETE.
	for _, stmt := range []string{
		"GRANT USAGE ON SCHEMA fi_c1_pending TO fi_ingest",
		"GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA fi_c1_pending TO fi_ingest",
		"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA fi_c1_pending TO fi_ingest",
		"REVOKE ALL ON fi_c1_pending.ingest_journal FROM fi_ingest",
        "GRANT SELECT ON fi_c1_pending.ingest_journal TO fi_ingest",
		"REVOKE ALL ON fi_c1_pending.generation_control FROM fi_ingest",
		"GRANT SELECT ON fi_c1_pending.generation_control TO fi_ingest",
		"GRANT INSERT (source_id, generation_id, receipt_sha256, transfer_sha256, record_count, batch_count) ON fi_c1_pending.generation_control TO fi_ingest",
        // The pre-C1 canonical migration explicitly grants fi_ingest
        // INSERT on all authoritative fi tables. C1's SQL writer MUST NOT
        // retain that authority after the operator-approved offline cutover.
        // Restrict it in the SAME transaction as Pending schema creation.
        // Existing canonical rows and SELECT access are not changed.
        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE, MAINTAIN ON ALL TABLES IN SCHEMA fi FROM fi_ingest",
        "ALTER DEFAULT PRIVILEGES FOR ROLE fi_owner IN SCHEMA fi REVOKE INSERT, UPDATE, DELETE, TRUNCATE, MAINTAIN ON TABLES FROM fi_ingest",
	} {
		if _, err = tx.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("C1 pending: atomic worker grants: %w", err)
		}
    }
    // Fail even when another inherited role, PUBLIC grant or table ownership
    // defeats the direct REVOKE. Do not activate C1 with ANY path to
    // authoritative fi mutations from the normal fi_ingest SQL worker.
    var canonicalWrites int64
    if err:=tx.QueryRow(ctx,`SELECT count(*) FROM pg_class c
        JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='fi' AND c.relkind IN ('r','p')
          AND (has_table_privilege('fi_ingest',c.oid,'INSERT')
            OR has_table_privilege('fi_ingest',c.oid,'UPDATE')
            OR has_table_privilege('fi_ingest',c.oid,'DELETE')
            OR has_table_privilege('fi_ingest',c.oid,'TRUNCATE')
            OR has_table_privilege('fi_ingest',c.oid,'MAINTAIN'))`).
        Scan(&canonicalWrites);err!=nil{return err}
    if canonicalWrites!=0{
        return fmt.Errorf("C1 pending: fi_ingest retains canonical write authority on %d fi relations",canonicalWrites)
    }
    return nil
}
