//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Local fi-sor PostgreSQL privilege preflight. A missing private grant must
// block signed START, not fail after ingest has prepared millions of rows.
// No permission is granted or changed by this preflight, and fi-ingest never
// receives a PostgreSQL connection.
package recordingest

import (
    "context"
    "errors"
    "fmt"

    "github.com/jackc/pgx/v5"
)

// c1ReadOnlyWorkerPrivatePrivileges requires the actual fi_ingest SQL role,
// the two pre-existing private schemas and every table/sequence privilege
// consumed by C1's five-family SQL worker pool. It performs no DDL or writes.
func c1ReadOnlyWorkerPrivatePrivileges(ctx context.Context,tx pgx.Tx)error{
    if ctx==nil||tx==nil{
        return errors.New("C1 fi-sor: SQL privilege preflight requires local read-only transaction")
    }
    var role string
    var projection,ledger bool
    if err:=tx.QueryRow(ctx,`SELECT current_user,
        to_regnamespace('fi_recovery_projection') IS NOT NULL,
        to_regnamespace('fi_recovery') IS NOT NULL`).
        Scan(&role,&projection,&ledger);err!=nil{return err}
    if role!="fi_ingest"||!projection||!ledger{
        return errors.New("C1 fi-sor: private schemas unavailable or SQL worker not fi_ingest")
    }
    var projectionUse,ledgerUse,projectionCreate,ledgerCreate bool
    if err:=tx.QueryRow(ctx,`SELECT
        has_schema_privilege(current_user,'fi_recovery_projection','USAGE'),
        has_schema_privilege(current_user,'fi_recovery','USAGE'),
        has_schema_privilege(current_user,'fi_recovery_projection','CREATE'),
        has_schema_privilege(current_user,'fi_recovery','CREATE')`).
        Scan(&projectionUse,&ledgerUse,&projectionCreate,&ledgerCreate);err!=nil{
        return err
    }
    if !projectionUse||!ledgerUse||projectionCreate||ledgerCreate{
        return errors.New("C1 fi-sor: SQL worker must have only private schema USAGE, never CREATE")
    }
    // An ACL-only survey can pass even if a required projector table
    // disappeared or was renamed: every surviving table might still have
    // SELECT/INSERT/UPDATE/DELETE. Demand the COMPLETE canonical-to-private
    // table-name/type mirror plus the exact five private recovery ledgers
    // before allowing START. This reads catalog metadata only.
    var canonicalTables,projectionTables,missingProjection,extraProjection int64
    var ledgerTables,missingLedger int64
    err:=tx.QueryRow(ctx,`
WITH canonical AS (
 SELECT c.relname,c.relkind FROM pg_class c
 JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='fi' AND c.relkind IN ('r','p')
), projection AS (
 SELECT c.relname,c.relkind FROM pg_class c
 JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='fi_recovery_projection' AND c.relkind IN ('r','p')
), ledger AS (
 SELECT c.relname FROM pg_class c
 JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='fi_recovery' AND c.relkind='r'
), expected_ledger(name) AS (
 VALUES ('verified_artifact_window'),('pending_source_record'),
        ('source_window'),('typed_window'),('projected_source_record')
)
SELECT
 (SELECT count(*) FROM canonical)::bigint,
 (SELECT count(*) FROM projection)::bigint,
 (SELECT count(*) FROM canonical c WHERE NOT EXISTS
    (SELECT 1 FROM projection p WHERE p.relname=c.relname AND p.relkind=c.relkind))::bigint,
 (SELECT count(*) FROM projection p WHERE NOT EXISTS
    (SELECT 1 FROM canonical c WHERE c.relname=p.relname AND c.relkind=p.relkind))::bigint,
 (SELECT count(*) FROM ledger)::bigint,
 (SELECT count(*) FROM expected_ledger e WHERE NOT EXISTS
    (SELECT 1 FROM ledger l WHERE l.relname=e.name))::bigint
`).Scan(&canonicalTables,&projectionTables,&missingProjection,
        &extraProjection,&ledgerTables,&missingLedger)
    if err!=nil{
        return fmt.Errorf("C1 fi-sor: read-only private schema mirror survey: %w",err)
    }
    if canonicalTables<40||projectionTables!=canonicalTables||
        missingProjection!=0||extraProjection!=0||ledgerTables!=5||
        missingLedger!=0{
        return fmt.Errorf("C1 fi-sor: incomplete private schema table mirror canonical=%d projection=%d missing=%d extra=%d ledger=%d missing_ledger=%d",
            canonicalTables,projectionTables,missingProjection,extraProjection,
            ledgerTables,missingLedger)
    }
    var tableCount,tableDenied,sequenceCount,sequenceDenied int64
    // CASE keeps PostgreSQL from evaluating has_sequence_privilege on
    // non-sequences, even when the query planner reorders predicates.
    if err:=tx.QueryRow(ctx,`
SELECT
 count(*) FILTER (WHERE c.relkind IN ('r','p'))::bigint,
 count(*) FILTER (WHERE c.relkind IN ('r','p') AND CASE
   WHEN c.relkind IN ('r','p') THEN NOT (
     has_table_privilege(current_user,c.oid,'SELECT')
     AND has_table_privilege(current_user,c.oid,'INSERT')
     AND has_table_privilege(current_user,c.oid,'UPDATE')
     AND has_table_privilege(current_user,c.oid,'DELETE'))
   ELSE false END)::bigint,
 count(*) FILTER (WHERE c.relkind='S')::bigint,
 count(*) FILTER (WHERE CASE
   WHEN c.relkind='S' THEN NOT (
     has_sequence_privilege(current_user,c.oid,'USAGE')
     AND has_sequence_privilege(current_user,c.oid,'SELECT'))
   ELSE false END)::bigint
FROM pg_class c
JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname IN ('fi_recovery_projection','fi_recovery')
`).Scan(&tableCount,&tableDenied,&sequenceCount,&sequenceDenied);err!=nil{
        return fmt.Errorf("C1 fi-sor: read-only PostgreSQL role privilege survey: %w",err)
    }
    if tableCount<45||tableDenied!=0||sequenceCount==0||sequenceDenied!=0{
        return fmt.Errorf("C1 fi-sor: incomplete private PostgreSQL worker permissions tables=%d inaccessible=%d sequences=%d inaccessible=%d",
            tableCount,tableDenied,sequenceCount,sequenceDenied)
    }
    return nil
}

func c1PreflightLocalSQLPrivileges(ctx context.Context,dsn string)error{
    conn,_,err:=openC1SoRLocalSQL(ctx,dsn,"")
    if err!=nil{return err}
    defer conn.Close(context.Background())
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{
        IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly,
    })
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    if err=c1ReadOnlyWorkerPrivatePrivileges(ctx,tx);err!=nil{return err}
    return tx.Commit(ctx)
}
