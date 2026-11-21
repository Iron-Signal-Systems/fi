//go:build fi_c1_sor_dev && fi_c1_schema_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Disposable PostgreSQL 18 service only: exercise real five-migration
// private projection and recovery schemas with forced DDL rollback.
// Never connect this test to the populated C220 SoR.
package recordingest

import (
    "context"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/freebsd/backendinstall"
    "github.com/jackc/pgx/v5"
)

func TestC1PrivateSchemaRealPostgres18AtomicDDL(t *testing.T){
    if os.Getenv("GITHUB_ACTIONS")!="true"||
        os.Getenv("FI_C1_SCHEMA_CI_ALLOW_DISPOSABLE")!="1"{
        t.Skip("isolated PostgreSQL18 schema fixture not selected")
    }
    dsn:=os.Getenv("FI_C1_SCHEMA_CI_ADMIN_DSN")
    if dsn==""{t.Fatal("STOP: isolated schema PostgreSQL connection required")}
    ctx,cancel:=context.WithTimeout(context.Background(),4*time.Minute)
    defer cancel()
    admin,err:=pgx.Connect(ctx,dsn)
    if err!=nil{t.Fatal(err)}
    defer admin.Close(context.Background())
    var who,db,port string
    var version int
    var canonical,private,ledger bool
    err=admin.QueryRow(ctx,`SELECT current_user,current_database(),
       current_setting('port'),current_setting('server_version_num')::int,
       to_regnamespace('fi') IS NOT NULL,
       to_regnamespace('fi_recovery_projection') IS NOT NULL,
       to_regnamespace('fi_recovery') IS NOT NULL`).
       Scan(&who,&db,&port,&version,&canonical,&private,&ledger)
    if err!=nil{t.Fatal(err)}
    if who!="fi_c1_schema_test"||db!="fi"||port!="5432"||
        version<180000||canonical||private||ledger{
        t.Fatalf("STOP: not a pristine disposable C1 schema PostgreSQL service role=%s database=%s port=%s version=%d schemas=%t/%t/%t",
            who,db,port,version,canonical,private,ledger)
    }
    for _,sql:=range []string{
       "CREATE ROLE fi_owner NOLOGIN",
       "CREATE ROLE fi_ingest LOGIN PASSWORD 'isolated-only-test'",
    }{
        if _,err=admin.Exec(ctx,sql);err!=nil{t.Fatal(err)}
    }
    migrations,err:=backendinstall.C1CanonicalSchemaMigrations()
    if err!=nil{t.Fatal(err)}
    for _,m:=range migrations{
        if _,err=admin.Exec(ctx,m.SQL,pgx.QueryExecModeSimpleProtocol);err!=nil{
            t.Fatalf("canonical fixture migration %s: %v",m.Name,err)
        }
    }
    var canonicalBefore int64
    if err=admin.QueryRow(ctx,`SELECT count(*) FROM information_schema.tables
        WHERE table_schema='fi'`).Scan(&canonicalBefore);err!=nil{t.Fatal(err)}
    if canonicalBefore<40{t.Fatal("canonical FI schema missing before C1 private DDL test")}

    // Inject a transaction failure after constructing EVERY proposed
    // private table, then prove both schemas have rolled back entirely.
    tx,err:=admin.Begin(ctx)
    if err!=nil{t.Fatal(err)}
    if err=c1InstallPrivateSchemaTx(ctx,tx);err!=nil{
        _=tx.Rollback(context.Background())
        t.Fatal(err)
    }
    if _,err=tx.Exec(ctx,"SELECT fi_c1_forced_rollback_missing_function()");err==nil{
        _=tx.Rollback(context.Background())
        t.Fatal("C1 intentionally failing DDL tail unexpectedly succeeded")
    }
    _=tx.Rollback(context.Background())
    if err=admin.QueryRow(ctx,`SELECT
      to_regnamespace('fi_recovery_projection') IS NOT NULL,
      to_regnamespace('fi_recovery') IS NOT NULL`).Scan(&private,&ledger);err!=nil{t.Fatal(err)}
    if private||ledger{t.Fatal("C1 private schema DDL rollback left partially created schemas")}

    tx,err=admin.Begin(ctx)
    if err!=nil{t.Fatal(err)}
    if err=c1InstallPrivateSchemaTx(ctx,tx);err!=nil{
        _=tx.Rollback(context.Background())
        t.Fatal(err)
    }
    if err=tx.Commit(ctx);err!=nil{t.Fatal(err)}
    var privateTables,ledgerTables,canonicalAfter int64
    if err=admin.QueryRow(ctx,`SELECT
       (SELECT count(*) FROM information_schema.tables WHERE table_schema='fi_recovery_projection'),
       (SELECT count(*) FROM information_schema.tables WHERE table_schema='fi_recovery'),
       (SELECT count(*) FROM information_schema.tables WHERE table_schema='fi')`).
       Scan(&privateTables,&ledgerTables,&canonicalAfter);err!=nil{t.Fatal(err)}
    if privateTables!=canonicalBefore||ledgerTables!=5||canonicalAfter!=canonicalBefore{
        t.Fatalf("C1 complete private schemas/canonical unchanged failure: private=%d expected=%d ledger=%d canonical=%d/%d",
            privateTables,canonicalBefore,ledgerTables,canonicalAfter,canonicalBefore)
    }
    // Verify the real fi-sor SQL worker DATABASE role can read and write
    // every new private table while retaining no schema CREATE privilege.
    // New private objects belong to the offline admin only; this is not a
    // GRANT to the fi-ingest jail or to canonical fi.
    var missingWorkerPrivileges int64
    err=admin.QueryRow(ctx,`
SELECT count(*) FROM pg_tables
WHERE schemaname IN ('fi_recovery_projection','fi_recovery')
 AND (
    NOT has_table_privilege('fi_ingest',
        format('%I.%I',schemaname,tablename),'SELECT')
 OR NOT has_table_privilege('fi_ingest',
        format('%I.%I',schemaname,tablename),'INSERT')
 OR NOT has_table_privilege('fi_ingest',
        format('%I.%I',schemaname,tablename),'UPDATE')
 OR NOT has_table_privilege('fi_ingest',
        format('%I.%I',schemaname,tablename),'DELETE')
 )`).Scan(&missingWorkerPrivileges)
    if err!=nil{t.Fatal(err)}
    if missingWorkerPrivileges!=0{
        t.Fatalf("fi-sor C1 SQL role cannot access %d private tables",missingWorkerPrivileges)
    }
    var projectionUsage,ledgerUsage,projectionCreate,ledgerCreate bool
    err=admin.QueryRow(ctx,`
SELECT has_schema_privilege('fi_ingest','fi_recovery_projection','USAGE'),
       has_schema_privilege('fi_ingest','fi_recovery','USAGE'),
       has_schema_privilege('fi_ingest','fi_recovery_projection','CREATE'),
       has_schema_privilege('fi_ingest','fi_recovery','CREATE')`).
       Scan(&projectionUsage,&ledgerUsage,&projectionCreate,&ledgerCreate)
    if err!=nil{t.Fatal(err)}
    if !projectionUsage||!ledgerUsage||projectionCreate||ledgerCreate{
        t.Fatal("C1 SQL role private-only USAGE / deny-CREATE contract invalid")
    }
    var missingSequences int64
    err=admin.QueryRow(ctx,`
SELECT count(*)
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE CASE
    WHEN c.relkind='S' AND n.nspname IN ('fi_recovery_projection','fi_recovery')
    THEN NOT has_sequence_privilege('fi_ingest',c.oid,'USAGE')
    ELSE false
 END`).
        Scan(&missingSequences)
    if err!=nil{t.Fatal(err)}
    if missingSequences!=0{
        t.Fatalf("C1 private identity sequences unavailable to SQL worker: %d",missingSequences)
    }
    // Don't rely only on pg_catalog ACL reporting: open an actual second
    // PostgreSQL session using the exact C1 fi-sor writer DATABASE role.
    // PostgreSQL must allow SELECT on both private schemas but reject
    // CREATE, proving new DDL is still restricted to the offline admin.
    workerCfg,err:=pgx.ParseConfig(dsn)
    if err!=nil{t.Fatal(err)}
    workerCfg.User="fi_ingest"
    workerCfg.Password="isolated-only-test"
    worker,err:=pgx.ConnectConfig(ctx,workerCfg)
    if err!=nil{t.Fatalf("C1 fi-sor private SQL role unable to connect: %v",err)}
    defer worker.Close(context.Background())
    for _,relation:=range []string{
        "fi_recovery_projection.source_record",
        "fi_recovery_projection.source_batch",
        "fi_recovery.typed_window",
    }{
        var observed int64
        if err=worker.QueryRow(ctx,"SELECT count(*) FROM "+relation).Scan(&observed);err!=nil{
            t.Fatalf("C1 fi-sor SQL role cannot read private %s: %v",relation,err)
        }
        if observed!=0{
            t.Fatalf("private schema SQL read unexpectedly nonempty in disposable fixture: %s",relation)
        }
    }
    if _,err=worker.Exec(ctx,`CREATE TABLE fi_recovery_projection.fi_c1_forbidden_worker_ddl
        (id bigint)`);err==nil{
        t.Fatal("C1 fi-sor runtime SQL role could create private schema objects")
    }
    var source,intake,accepted int64
    if err=admin.QueryRow(ctx,`SELECT
       (SELECT count(*) FROM fi_recovery_projection.source_record),
       (SELECT count(*) FROM fi.source_record),
       (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')`).
       Scan(&source,&intake,&accepted);err!=nil{t.Fatal(err)}
    if source!=0||intake!=0||accepted!=0{
        t.Fatal("C1 private schema installation created source or Accepted journal rows")
    }
    // The exact schemas also retain FK contracts, source identity uniqueness,
    // and private source-indexes on the new PostgreSQL 18 instance.
    var constraints int64
    if err=admin.QueryRow(ctx,`SELECT count(*) FROM pg_constraint c
       JOIN pg_namespace n ON n.oid=c.connamespace
       WHERE n.nspname='fi_recovery_projection' AND c.contype='f'`).
       Scan(&constraints);err!=nil{t.Fatal(err)}
    if constraints<20{t.Fatalf("C1 private relational foreign key graph unexpectedly incomplete: %d",constraints)}
    // Don't allow a second schema creation to overwrite existing private
    // SQL state; the guarded entrypoint separately forbids existing schemas.
    retry,err:=admin.Begin(ctx)
    if err!=nil{t.Fatal(err)}
    if err=c1InstallPrivateSchemaTx(ctx,retry);err==nil{
        _=retry.Rollback(context.Background())
        t.Fatal("C1 private schema installation unexpectedly overwrote already created schema")
    }
    _=retry.Rollback(context.Background())
    t.Log("PASS: disposable PostgreSQL18 C1 full private schema atomic rollback/install, canonical FI untouched")
    _=filepath.Separator
    _=strings.Builder{}
}
