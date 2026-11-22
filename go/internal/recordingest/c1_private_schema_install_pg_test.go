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
    "bytes"
    "encoding/hex"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
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
    // A signed generation that has not been published must remain
    // FinalVerified, not FinalAccepted. Exercise the SAME read-only SQL
    // and columns against the actual 49-table FI PostgreSQL18 DDL.
    canonicalRead,err:=admin.BeginTx(ctx,pgx.TxOptions{
        IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly,
    })
    if err!=nil{t.Fatal(err)}
    finalStatus,finalErr:=c1CanonicalStatusInSnapshot(ctx,canonicalRead,
        "fi-c1-disposable-no-source","no-canonical-generation",
        strings.Repeat("a",64))
    if finalErr!=nil{
        _=canonicalRead.Rollback(context.Background())
        t.Fatalf("real PostgreSQL18 canonical Accepted readback query invalid: %v",finalErr)
    }
    if err=canonicalRead.Commit(ctx);err!=nil{t.Fatal(err)}
    if finalStatus!=c1handoff.FinalVerified{
        t.Fatal("real canonical SoR falsely declared an unaccepted generation Accepted")
    }

    // This real PostgreSQL18 positive fixture is TRANSACTIONAL AND ROLLED
    // BACK: it cannot alter the canonical baseline or original C220.
    txAccepted,e:=admin.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.ReadCommitted})
    if e!=nil{t.Fatal(e)}
    sha:=bytes.Repeat([]byte{0x43},32)
    transfer:=bytes.Repeat([]byte{0x29},32)
    other:=bytes.Repeat([]byte{0x53},32)
    src,gen:="fi-c1-positive-ci-source","fi-c1-positive-ci-generation"
    _,e=txAccepted.Exec(ctx,`INSERT INTO fi.recorded_generation (
      receipt_version,descriptor_version,source_id,generation_id,
      canonical_version,data_encoding,artifact_count,source_bytes,
      canonical_bytes,canonical_sha256,encoded_data_bytes,
      encoded_data_sha256,metadata_bytes,metadata_sha256,
      transfer_bytes,transfer_sha256,batch_count,data_bytes,record_count,
      receipt_bytes,receipt_sha256,ingest_version)
      VALUES ('fi-generation-recorded/0.1','fi-generation-descriptor/0.1',
      $1,$2,'fi-canonical/0.1','none',2,128,128,$3,64,$4,32,$5,
      116,$6,1,64,1,120,$7,'ci-only')`,
      src,gen,other,other,other,transfer,sha)
    if e!=nil{
       _=txAccepted.Rollback(context.Background())
       t.Fatalf("create disposable canonical generation fixture: %v",e)
    }
    if status,e:=c1CanonicalStatusInSnapshot(ctx,txAccepted,src,gen,
        hex.EncodeToString(sha));e==nil||status!=c1handoff.FinalNone{
        _=txAccepted.Rollback(context.Background())
        t.Fatal("canonical generation lacking Accepted journal was accepted")
    }
    _,e=txAccepted.Exec(ctx,`INSERT INTO fi.ingest_journal(
      attempt_id,event_sequence,source_id,generation_id,transfer_sha256,
      outcome,stage,records_seen,records_committed,ingest_version)
      VALUES ('c1-fixture',2,$1,$2,$3,'Accepted','GenerationAccepted',1,1,'ci-only')`,
      src,gen,transfer)
    if e!=nil{
       _=txAccepted.Rollback(context.Background())
       t.Fatalf("create disposable canonical Accepted journal fixture: %v",e)
    }
    acceptedStatus,e:=c1CanonicalStatusInSnapshot(ctx,txAccepted,src,gen,
        hex.EncodeToString(sha))
    if e!=nil||acceptedStatus!=c1handoff.FinalAccepted{
       _=txAccepted.Rollback(context.Background())
       t.Fatalf("C1 exact real canonical Accepted journal rejected: %d %v",acceptedStatus,e)
    }
    _,e=txAccepted.Exec(ctx,`INSERT INTO fi.ingest_journal(
      attempt_id,event_sequence,source_id,generation_id,transfer_sha256,
      outcome,stage,records_seen,records_committed,ingest_version)
      VALUES ('c1-fixture-duplicate',2,$1,$2,$3,'Accepted','GenerationAccepted',1,1,'ci-only')`,
      src,gen,transfer)
    if e!=nil{
       _=txAccepted.Rollback(context.Background())
       t.Fatalf("create duplicate disposable Accepted journal: %v",e)
    }
    if status,e:=c1CanonicalStatusInSnapshot(ctx,txAccepted,src,gen,
        hex.EncodeToString(sha));e==nil||status!=c1handoff.FinalNone{
        _=txAccepted.Rollback(context.Background())
        t.Fatal("C1 accepted duplicate canonical Accepted journal")
    }
    if e=txAccepted.Rollback(context.Background());e!=nil{t.Fatal(e)}
    // After rollback, even source metadata must have disappeared.
    afterRollback,e:=admin.BeginTx(ctx,pgx.TxOptions{AccessMode:pgx.ReadOnly})
    if e!=nil{t.Fatal(e)}
    status,e:=c1CanonicalStatusInSnapshot(ctx,afterRollback,src,gen,
        hex.EncodeToString(sha))
    if e!=nil||status!=c1handoff.FinalVerified{
       _=afterRollback.Rollback(context.Background())
       t.Fatalf("disposable test left canonical Accepted rows after rollback: %d %v",status,e)
    }
    if e=afterRollback.Commit(ctx);e!=nil{t.Fatal(e)}

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
    readOnly,e:=worker.BeginTx(ctx,pgx.TxOptions{
        IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly,
    })
    if e!=nil{t.Fatal(e)}
    if e=c1ReadOnlyWorkerPrivatePrivileges(ctx,readOnly);e!=nil{
        t.Fatalf("C1 fi-sor startup SQL role preflight rejected valid schema: %v",e)
    }
    if e=readOnly.Commit(ctx);e!=nil{t.Fatal(e)}
    // A role can retain every table ACL after a schema table is renamed.
    // The START gate must reject a missing *specific* projector even when
    // the total table count and all SQL grants are unchanged.
    if _,err=admin.Exec(ctx,`ALTER TABLE fi_recovery_projection.collector_identity
        RENAME TO fi_c1_intentionally_missing_collector_identity`);err!=nil{
        t.Fatal(err)
    }
    mirrorTx,e:=worker.BeginTx(ctx,pgx.TxOptions{
        IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly,
    })
    if e!=nil{t.Fatal(e)}
    mirrorErr:=c1ReadOnlyWorkerPrivatePrivileges(ctx,mirrorTx)
    _=mirrorTx.Rollback(context.Background())
    if mirrorErr==nil||!strings.Contains(mirrorErr.Error(),"incomplete private schema table mirror"){
        t.Fatalf("C1 START accepted renamed private projector despite valid table ACLs: %v",mirrorErr)
    }
    if _,err=admin.Exec(ctx,`ALTER TABLE fi_recovery_projection.fi_c1_intentionally_missing_collector_identity
        RENAME TO collector_identity`);err!=nil{
        t.Fatal(err)
    }
    restoredMirrorTx,e:=worker.BeginTx(ctx,pgx.TxOptions{
        IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly,
    })
    if e!=nil{t.Fatal(e)}
    if e=c1ReadOnlyWorkerPrivatePrivileges(ctx,restoredMirrorTx);e!=nil{
        t.Fatalf("C1 START rejected restored exact projector schema: %v",e)
    }
    if e=restoredMirrorTx.Commit(ctx);e!=nil{t.Fatal(e)}
    // Keep the recovery ledger equally exact. A renamed marker retains all
    // permissions but must never count as a valid published progress table.
    if _,err=admin.Exec(ctx,`ALTER TABLE fi_recovery.typed_window
        RENAME TO fi_c1_intentionally_missing_typed_window`);err!=nil{
        t.Fatal(err)
    }
    ledgerTx,e:=worker.BeginTx(ctx,pgx.TxOptions{
        IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly,
    })
    if e!=nil{t.Fatal(e)}
    ledgerErr:=c1ReadOnlyWorkerPrivatePrivileges(ctx,ledgerTx)
    _=ledgerTx.Rollback(context.Background())
    if ledgerErr==nil||!strings.Contains(ledgerErr.Error(),"incomplete private schema table mirror"){
        t.Fatalf("C1 START accepted missing recovery ledger marker: %v",ledgerErr)
    }
    if _,err=admin.Exec(ctx,`ALTER TABLE fi_recovery.fi_c1_intentionally_missing_typed_window
        RENAME TO typed_window`);err!=nil{
        t.Fatal(err)
    }
    restoredLedgerTx,e:=worker.BeginTx(ctx,pgx.TxOptions{
        IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly,
    })
    if e!=nil{t.Fatal(e)}
    if e=c1ReadOnlyWorkerPrivatePrivileges(ctx,restoredLedgerTx);e!=nil{
        t.Fatalf("C1 START rejected restored recovery ledger: %v",e)
    }
    if e=restoredLedgerTx.Commit(ctx);e!=nil{t.Fatal(e)}
    if _,err=worker.Exec(ctx,`CREATE TABLE fi_recovery_projection.fi_c1_forbidden_worker_ddl
        (id bigint)`);err==nil{
        t.Fatal("C1 fi-sor runtime SQL role could create private schema objects")
    }
    // A real PostgreSQL ACL regression must block signed C1 START even
    // if SELECT and all other private grants remain valid. Restore the
    // exact INSERT privilege after proving the runtime gate fails closed.
    if _,err=admin.Exec(ctx,`REVOKE INSERT ON fi_recovery_projection.source_record FROM fi_ingest`);err!=nil{
        t.Fatal(err)
    }
    deniedTx,e:=worker.BeginTx(ctx,pgx.TxOptions{
        IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly,
    })
    if e!=nil{t.Fatal(e)}
    deniedErr:=c1ReadOnlyWorkerPrivatePrivileges(ctx,deniedTx)
    _=deniedTx.Rollback(context.Background())
    if deniedErr==nil||!strings.Contains(deniedErr.Error(),"incomplete private PostgreSQL worker permissions"){
        t.Fatalf("C1 START would accept missing SourceParent INSERT privilege: %v",deniedErr)
    }
    if _,err=admin.Exec(ctx,`GRANT INSERT ON fi_recovery_projection.source_record TO fi_ingest`);err!=nil{
        t.Fatal(err)
    }
    recoveredTx,e:=worker.BeginTx(ctx,pgx.TxOptions{
        IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly,
    })
    if e!=nil{t.Fatal(e)}
    if e=c1ReadOnlyWorkerPrivatePrivileges(ctx,recoveredTx);e!=nil{
        t.Fatalf("C1 START rejected restored exact private SQL grants: %v",e)
    }
    if e=recoveredTx.Commit(ctx);e!=nil{t.Fatal(e)}
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
    // The NEW governed pending representation is installed only inside
    // this disposable PostgreSQL18 fixture. First prove complete rollback,
    // then commit its DDL and audit every role/authority boundary.
    pendingTx,e:=admin.Begin(ctx)
    if e!=nil{t.Fatal(e)}
    if e=c1InstallGovernedPendingSchemaTx(ctx,pendingTx);e!=nil{
        _=pendingTx.Rollback(context.Background())
        t.Fatalf("C1 pending PostgreSQL18 migration: %v",e)
    }
    if _,e=pendingTx.Exec(ctx,"SELECT fi_c1_force_pending_ddl_rollback()");e==nil{
        _=pendingTx.Rollback(context.Background())
        t.Fatal("C1 pending intentional rollback injection unexpectedly passed")
    }
    _=pendingTx.Rollback(context.Background())
    var pendingExists bool
    if e=admin.QueryRow(ctx,"SELECT to_regnamespace('fi_c1_pending') IS NOT NULL").Scan(&pendingExists);e!=nil{t.Fatal(e)}
    if pendingExists{t.Fatal("C1 governed pending migration left partial DDL after rollback")}
    pendingTx,e=admin.Begin(ctx)
    if e!=nil{t.Fatal(e)}
    if e=c1InstallGovernedPendingSchemaTx(ctx,pendingTx);e!=nil{
        _=pendingTx.Rollback(context.Background())
        t.Fatalf("C1 governed pending full DDL failed in PostgreSQL18: %v",e)
    }
    if e=pendingTx.Commit(ctx);e!=nil{t.Fatal(e)}
    var pendingTables,canonicalAfterPending int64
    if e=admin.QueryRow(ctx,`SELECT
       (SELECT count(*) FROM information_schema.tables WHERE table_schema='fi_c1_pending'),
       (SELECT count(*) FROM information_schema.tables WHERE table_schema='fi')`).
       Scan(&pendingTables,&canonicalAfterPending);e!=nil{t.Fatal(e)}
    if pendingTables!=canonicalBefore+1||canonicalAfterPending!=canonicalBefore{
        t.Fatalf("C1 governed pending must mirror canonical plus one control: pending=%d expected=%d canonical=%d/%d",
            pendingTables,canonicalBefore+1,canonicalAfterPending,canonicalBefore)
    }
    var sqlWorkerUsage,sqlWorkerCreate,sqlWorkerSourceRead,sqlWorkerSourceInsert bool
    var sqlWorkerControlRead,sqlWorkerControlWrite,sqlWorkerJournalWrite bool
    var sqlWorkerControlIdentityInsert,sqlWorkerControlProofInsert bool
    e=admin.QueryRow(ctx,`SELECT
      has_schema_privilege('fi_ingest','fi_c1_pending','USAGE'),
      has_schema_privilege('fi_ingest','fi_c1_pending','CREATE'),
      has_table_privilege('fi_ingest','fi_c1_pending.source_record','SELECT'),
      has_table_privilege('fi_ingest','fi_c1_pending.source_record','INSERT'),
      has_table_privilege('fi_ingest','fi_c1_pending.generation_control','SELECT'),
      has_table_privilege('fi_ingest','fi_c1_pending.generation_control','UPDATE'),
      has_column_privilege('fi_ingest','fi_c1_pending.generation_control','source_id','INSERT'),
      has_column_privilege('fi_ingest','fi_c1_pending.generation_control','state','INSERT'),
      has_table_privilege('fi_ingest','fi_c1_pending.ingest_journal','INSERT')`).
      Scan(&sqlWorkerUsage,&sqlWorkerCreate,&sqlWorkerSourceRead,
        &sqlWorkerSourceInsert,&sqlWorkerControlRead,&sqlWorkerControlWrite,
        &sqlWorkerControlIdentityInsert,&sqlWorkerControlProofInsert,
        &sqlWorkerJournalWrite)
    if e!=nil{t.Fatal(e)}
    if !sqlWorkerUsage||sqlWorkerCreate||!sqlWorkerSourceRead||
        !sqlWorkerSourceInsert||!sqlWorkerControlRead||
        sqlWorkerControlWrite||!sqlWorkerControlIdentityInsert||
        sqlWorkerControlProofInsert||sqlWorkerJournalWrite{
        t.Fatal("C1 governed pending worker could create objects, modify verifier, forge journal or could not write source")
    }
    // The real fi-sor START gate must also reject a renamed relation,
    // not merely report that every surviving table retains its ACL.
    pendingGateTx,e:=worker.BeginTx(ctx,pgx.TxOptions{
        IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly,
    })
    if e!=nil{t.Fatal(e)}
    if e=c1ReadOnlyGovernedPendingWorkerPrivileges(ctx,pendingGateTx);e!=nil{
        _=pendingGateTx.Rollback(context.Background())
        t.Fatalf("C1 pending read-only START privilege gate: %v",e)
    }
    if e=pendingGateTx.Commit(ctx);e!=nil{t.Fatal(e)}
    if _,e=admin.Exec(ctx,`ALTER TABLE fi_c1_pending.file_observation
        RENAME TO fi_c1_removed_file_observation`);e!=nil{t.Fatal(e)}
    missingGateTx,e:=worker.BeginTx(ctx,pgx.TxOptions{
        IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly,
    })
    if e!=nil{t.Fatal(e)}
    missingGateErr:=c1ReadOnlyGovernedPendingWorkerPrivileges(ctx,missingGateTx)
    _=missingGateTx.Rollback(context.Background())
    if missingGateErr==nil{
        t.Fatal("C1 pending START accepted missing signed File projection table")
    }
    if _,e=admin.Exec(ctx,`ALTER TABLE fi_c1_pending.fi_c1_removed_file_observation
        RENAME TO file_observation`);e!=nil{t.Fatal(e)}
    var pendingFKs int64
    if e=admin.QueryRow(ctx,`SELECT count(*) FROM pg_constraint c
        JOIN pg_namespace n ON n.oid=c.connamespace
        WHERE n.nspname='fi_c1_pending' AND c.contype='f'`).Scan(&pendingFKs);e!=nil{t.Fatal(e)}
    if pendingFKs<20{t.Fatalf("C1 pending relational FK graph incomplete: %d",pendingFKs)}
    // Create two independently signed-looking metadata fixtures in a
    // transaction, then prove the unique unresolved-generation fence.
    // The entire fixture is rolled back: no caller can treat it as custody.
    lifecycleTx,e:=admin.Begin(ctx)
    if e!=nil{t.Fatal(e)}
    _,e=lifecycleTx.Exec(ctx,`INSERT INTO fi_c1_pending.recorded_generation (
      receipt_version,descriptor_version,source_id,generation_id,
      canonical_version,data_encoding,artifact_count,source_bytes,
      canonical_bytes,canonical_sha256,encoded_data_bytes,
      encoded_data_sha256,metadata_bytes,metadata_sha256,
      transfer_bytes,transfer_sha256,batch_count,data_bytes,record_count,
      receipt_bytes,receipt_sha256,ingest_version)
      SELECT 'fixture','fixture','ci-source',g.gen,'fixture','none',
      2,128,128,decode(repeat(g.digest,32),'hex'),64,decode(repeat(g.digest,32),'hex'),
      32,decode(repeat(g.digest,32),'hex'),116,decode(repeat(g.digest,32),'hex'),
      1,64,1,120,decode(repeat(g.digest,32),'hex'),'ci-only'
      FROM (VALUES ('ci-generation-1','11'),('ci-generation-2','22')) AS g(gen,digest)`)
    if e!=nil{
        _=lifecycleTx.Rollback(context.Background())
        t.Fatalf("C1 pending signed-identity FK fixture: %v",e)
    }
    insertControl:=`INSERT INTO fi_c1_pending.generation_control(
        source_id,generation_id,receipt_sha256,transfer_sha256,record_count,batch_count)
        SELECT source_id,generation_id,receipt_sha256,transfer_sha256,record_count,batch_count
        FROM fi_c1_pending.recorded_generation WHERE generation_id=$1`
    if _,e=lifecycleTx.Exec(ctx,insertControl,"ci-generation-1");e!=nil{t.Fatal(e)}
    if _,e=lifecycleTx.Exec(ctx,"SAVEPOINT pending_second");e!=nil{t.Fatal(e)}
    if _,e=lifecycleTx.Exec(ctx,insertControl,"ci-generation-2");e==nil{
        _=lifecycleTx.Rollback(context.Background())
        t.Fatal("C1 pending admitted two unresolved generations")
    }
    if _,e=lifecycleTx.Exec(ctx,"ROLLBACK TO SAVEPOINT pending_second");e!=nil{t.Fatal(e)}
    if _,e=lifecycleTx.Exec(ctx,`UPDATE fi_c1_pending.generation_control
        SET state='Retired',verifier_b_receipt_sha256=receipt_sha256,
            verifier_b_at=clock_timestamp() WHERE generation_id='ci-generation-1'`);e!=nil{t.Fatal(e)}
    if _,e=lifecycleTx.Exec(ctx,insertControl,"ci-generation-2");e!=nil{
        _=lifecycleTx.Rollback(context.Background())
        t.Fatalf("C1 pending failed to admit next generation after reviewed retirement: %v",e)
    }
    if e=lifecycleTx.Rollback(context.Background());e!=nil{t.Fatal(e)}
    var pendingControls,canonicalAccepted int64
    if e=admin.QueryRow(ctx,`SELECT
        (SELECT count(*) FROM fi_c1_pending.generation_control),
        (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')`).
        Scan(&pendingControls,&canonicalAccepted);e!=nil{t.Fatal(e)}
    if pendingControls!=0||canonicalAccepted!=0{
        t.Fatal("C1 pending CI fixture left state or canonical Accepted journal")
    }
    t.Log("PASS: disposable PostgreSQL18 governed pending 49-table mirror, DDL rollback, SQL worker ACLs and unresolved-generation fence")
    t.Log("PASS: disposable PostgreSQL18 C1 full private schema atomic rollback/install, canonical FI untouched")
    _=filepath.Separator
    _=strings.Builder{}
}
