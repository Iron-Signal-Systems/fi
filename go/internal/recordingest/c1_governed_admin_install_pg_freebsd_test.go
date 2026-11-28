//go:build freebsd && fi_c1_sor_dev && fi_c1_schema_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Fresh SEPARATE disposable FreeBSD PostgreSQL18 cluster on private Unix
// socket. Test actual one-shot existing-SoR Pending + role installer. This
// must never run against C220 or any operational FI PostgreSQL cluster.
package recordingest

import (
    "context"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "github.com/jackc/pgx/v5"
)

func TestC1GovernedPendingOfflineInstallerFreshPostgres18(t *testing.T){
    if os.Getenv("GITHUB_ACTIONS")!="true"||
        os.Getenv("FI_C1_SCHEMA_CI_ALLOW_DISPOSABLE")!="1"{
        t.Skip("offline C1 governed install is for disposable FreeBSD CI")
    }
    dsn:=os.Getenv("FI_C1_CI_OFFLINE_INSTALL_DSN")
    if dsn==""{t.Skip("separate disposable offline installer cluster not selected")}
    cfg,err:=pgx.ParseConfig(dsn)
    if err!=nil{t.Fatal(err)}
    if cfg.User!="fi_c1_schema_test"||cfg.Database!="fi"||cfg.Port!=5434||
        !filepath.IsAbs(cfg.Host)||!strings.HasPrefix(cfg.Host,"/var/tmp/fi-c1-pg18-vm.")||
        !strings.HasSuffix(cfg.Host,"/offline-socket")||
        os.Getenv("FI_C1_CI_OFFLINE_INSTALL_APPROVED")!="ISOLATED_SECOND_PG18_CLUSTER_ONLY"{
        t.Fatal("STOP: offline governed install is not in its dedicated disposable PostgreSQL fixture")
    }
    ctx,cancel:=context.WithTimeout(context.Background(),2*time.Minute)
    defer cancel()
    admin,err:=pgx.ConnectConfig(ctx,cfg)
    if err!=nil{t.Fatal(err)}
    defer admin.Close(context.Background())
    var who,db string
    var isLocal,standby bool
    var version int
    if err=admin.QueryRow(ctx,`SELECT current_user,current_database(),
        inet_server_addr() IS NULL,pg_is_in_recovery(),
        current_setting('server_version_num')::integer`).
        Scan(&who,&db,&isLocal,&standby,&version);err!=nil{t.Fatal(err)}
    if who!="fi_c1_schema_test"||db!="fi"||!isLocal||standby||
        version<180000||version>=190000{
        t.Fatal("STOP: offline installer positive test not on fresh local PostgreSQL18")
    }
    // Simulate a hardened existing SoR which has removed the default
    // database TEMP grant from PUBLIC. The canonical publisher must receive
    // its own narrow TEMP privilege for the existing FK-remap temporary maps.
    if _,err=admin.Exec(ctx,"REVOKE TEMPORARY ON DATABASE fi FROM PUBLIC");err!=nil{t.Fatal(err)}
    // Own the existing canonical schema before installing C1. Preserve its
    // original data throughout the governed-only DDL and role transaction.
    if _,err=admin.Exec(ctx,"CREATE ROLE fi_owner NOLOGIN");err!=nil{t.Fatal(err)}
    // Existing canonical FI migrations explicitly grant fi_ingest table
    // rights, so a populated-SoR fixture must have that preexisting
    // restricted SQL role before any C1 Pending installer is invoked.
    if _,err=admin.Exec(ctx,`CREATE ROLE fi_ingest LOGIN NOSUPERUSER
        NOCREATEDB NOCREATEROLE NOREPLICATION`);err!=nil{t.Fatal(err)}
    migrations,err:=c1CanonicalSchemaMigrations()
    if err!=nil{t.Fatal(err)}
    for _,m:=range migrations{
        if _,err=admin.Exec(ctx,m.SQL,pgx.QueryExecModeSimpleProtocol);err!=nil{
            t.Fatalf("disposable canonical FI migration %s: %v",m.Name,err)
        }
    }
    if _,err=admin.Exec(ctx,`INSERT INTO fi.recorded_generation (
        receipt_version,descriptor_version,source_id,generation_id,
        canonical_version,data_encoding,artifact_count,source_bytes,
        canonical_bytes,canonical_sha256,encoded_data_bytes,encoded_data_sha256,
        metadata_bytes,metadata_sha256,transfer_bytes,transfer_sha256,
        batch_count,data_bytes,record_count,receipt_bytes,receipt_sha256,ingest_version)
        VALUES ('fi-generation-recorded/0.1','fi-generation-descriptor/0.1',
        'fi-c1-admin-original','fi-c1-admin-preserved','fi-canonical/0.1',
        'none',2,128,128,decode(repeat('22',32),'hex'),64,
        decode(repeat('22',32),'hex'),32,decode(repeat('22',32),'hex'),
        116,decode(repeat('33',32),'hex'),1,64,1,120,
        decode(repeat('44',32),'hex'),'ci-only')`);err!=nil{t.Fatal(err)}
    if _,err=admin.Exec(ctx,`INSERT INTO fi.ingest_journal (
        attempt_id,event_sequence,source_id,generation_id,transfer_sha256,
        outcome,stage,records_seen,records_committed,ingest_version)
        VALUES ('fi-c1-admin-existing-accepted',2,'fi-c1-admin-original',
        'fi-c1-admin-preserved',decode(repeat('33',32),'hex'),
        'Accepted','GenerationAccepted',1,1,'ci-only')`);err!=nil{t.Fatal(err)}
    before:=func()(int64,int64,error){
        var generations,accepted int64
        err:=admin.QueryRow(ctx,`SELECT
          (SELECT count(*) FROM fi.recorded_generation),
          (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')`).
          Scan(&generations,&accepted)
        return generations,accepted,err
    }
    generations,accepted,err:=before()
    if err!=nil||generations!=1||accepted!=1{
        t.Fatalf("canonical FI preservation fixture missing: %d/%d %v",generations,accepted,err)
    }

    // Mandatory rollback injection: Pending and new publisher must not
    // escape the failed transaction; the original fi_ingest SQL role and
    // all preexisting canonical FI history must remain untouched.
    tx,err:=admin.Begin(ctx)
    if err!=nil{t.Fatal(err)}
    if err=c1InstallGovernedPendingSchemaTx(ctx,tx);err!=nil{
        _=tx.Rollback(context.Background());t.Fatal(err)
    }
    for _,ddl:=range C1CanonicalPublisherRolePlan(){
        if _,err=tx.Exec(ctx,ddl);err!=nil{
            _=tx.Rollback(context.Background());t.Fatal(err)
        }
    }
    if _,err=tx.Exec(ctx,"SELECT fi_c1_intentionally_missing_ddl_finalizer()");err==nil{
        _=tx.Rollback(context.Background())
        t.Fatal("disposable SQL DDL failure injection unexpectedly succeeded")
    }
    _=tx.Rollback(context.Background())
    var stage,worker,publisher bool
    if err=admin.QueryRow(ctx,`SELECT
        to_regnamespace('fi_c1_pending') IS NOT NULL,
        EXISTS(SELECT 1 FROM pg_roles WHERE rolname='fi_ingest'),
        EXISTS(SELECT 1 FROM pg_roles WHERE rolname='fi_c1_publisher')`).
        Scan(&stage,&worker,&publisher);err!=nil{t.Fatal(err)}
    if stage||!worker||publisher{
        t.Fatal("failed offline install left Pending/publisher objects or changed the preexisting canonical SQL role")
    }
    if generations2,accepted2,e:=before();e!=nil||generations2!=generations||accepted2!=accepted{
        t.Fatal("forced offline DDL rollback changed preexisting FI canonical data")
    }

    // A connected original FI SQL worker is a hard offline-cutover STOP.
    // This protects even inactive legacy sessions from having canonical
    // INSERT rights revoked underneath their running backend.
    workerConfig:=cfg.Copy()
    workerConfig.User="fi_ingest"
    activeWorker,activeErr:=pgx.ConnectConfig(ctx,workerConfig)
    if activeErr!=nil{t.Fatal(activeErr)}
    blocked:=InstallC1GovernedPendingOnExistingSoR(ctx,admin)
    _=activeWorker.Close(context.Background())
    if blocked==nil||!strings.Contains(blocked.Error(),"SQL sessions still connected"){
        t.Fatalf("offline C1 governed cutover accepted a connected old FI SQL worker: %v",blocked)
    }
    var notInstalled bool
    if err=admin.QueryRow(ctx,"SELECT to_regnamespace('fi_c1_pending') IS NULL").Scan(&notInstalled);err!=nil||!notInstalled{
        t.Fatal("rejected active SQL cutover left a partial governed schema")
    }

    // Positive path invokes the exact real offline installer only after
    // every prior FI SQL worker has disconnected from canonical fi.
    if err=InstallC1GovernedPendingOnExistingSoR(ctx,admin);err!=nil{
        t.Fatalf("governed C1 Pending/role install failed: %v",err)
    }
    var pendingTables,canonicalTables int64
    if err=admin.QueryRow(ctx,`SELECT
      (SELECT count(*) FROM information_schema.tables
       WHERE table_schema='fi_c1_pending'),
      (SELECT count(*) FROM information_schema.tables
       WHERE table_schema='fi')`).
       Scan(&pendingTables,&canonicalTables);err!=nil{t.Fatal(err)}
    if pendingTables!=52||canonicalTables!=51{
        t.Fatalf("one-shot governed install altered canonical schema or omitted Pending: pending=%d canonical=%d",
            pendingTables,canonicalTables)
    }
    if generations2,accepted2,e:=before();e!=nil||generations2!=1||accepted2!=1{
        t.Fatal("offline C1 governed installation modified canonical original Accepted history")
    }
    var publisherTemp,workerTemp bool
    if err=admin.QueryRow(ctx,`SELECT
       has_database_privilege('fi_c1_publisher','fi','TEMPORARY'),
       has_database_privilege('fi_ingest','fi','TEMPORARY')`).
       Scan(&publisherTemp,&workerTemp);err!=nil{t.Fatal(err)}
    if !publisherTemp||workerTemp{
        t.Fatal("C1 governed install did not isolate PostgreSQL TEMP maps to publisher")
    }
    var workerSourceInsert,workerJournalRead,workerJournalWrite,workerCanonicalWrite,
        publisherCanonicalLock,publisherCanonicalWrite,publisherCanonicalTruncate,
        publisherPendingTruncate bool
    err=admin.QueryRow(ctx,`SELECT
       has_table_privilege('fi_ingest','fi_c1_pending.source_record','INSERT'),
       has_table_privilege('fi_ingest','fi_c1_pending.ingest_journal','SELECT'),
       has_table_privilege('fi_ingest','fi_c1_pending.ingest_journal','INSERT'),
       has_table_privilege('fi_ingest','fi.source_record','INSERT'),
       has_table_privilege('fi_c1_publisher','fi.source_record','MAINTAIN'),
       has_table_privilege('fi_c1_publisher','fi.ingest_journal','INSERT'),
       has_table_privilege('fi_c1_publisher','fi.source_record','TRUNCATE'),
       has_table_privilege('fi_c1_publisher','fi_c1_pending.source_record','TRUNCATE')`).
       Scan(&workerSourceInsert,&workerJournalRead,&workerJournalWrite,
           &workerCanonicalWrite,&publisherCanonicalLock,&publisherCanonicalWrite,
           &publisherCanonicalTruncate,&publisherPendingTruncate)
    if err!=nil{t.Fatal(err)}
    if !workerSourceInsert||!workerJournalRead||workerJournalWrite||
        workerCanonicalWrite||!publisherCanonicalLock||!publisherCanonicalWrite||
        publisherCanonicalTruncate||!publisherPendingTruncate{
        t.Fatal("installed fi_ingest/publisher PostgreSQL privileges violate separated SQL roles")
    }
    publisherCfg:=cfg.Copy()
    publisherCfg.User=c1PublisherRole
    publisherConn,err:=pgx.ConnectConfig(ctx,publisherCfg)
    if err!=nil{t.Fatal(err)}
    defer publisherConn.Close(context.Background())
    read,err:=publisherConn.BeginTx(ctx,pgx.TxOptions{
        IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly,
    })
    if err!=nil{t.Fatal(err)}
    if err=c1ReadOnlyPublisherPrivileges(ctx,read);err!=nil{
        _=read.Rollback(context.Background())
        t.Fatalf("actual offline publisher role cannot pass canonical SQL preflight: %v",err)
    }
    if err=read.Commit(ctx);err!=nil{t.Fatal(err)}
    // A read-only ACL check is insufficient: actually create the ephemeral
    // mapping relation the canonical publisher requires, then roll it back.
    probe,err:=publisherConn.Begin(ctx)
    if err!=nil{t.Fatal(err)}
    if _,err=probe.Exec(ctx,
        "CREATE TEMP TABLE fi_c1_publisher_fk_map_probe (old_id bigint, new_id bigint) ON COMMIT DROP");err!=nil{
        _=probe.Rollback(context.Background())
        t.Fatalf("C1 publisher cannot create temporary FK remap table: %v",err)
    }
    if err=probe.Rollback(ctx);err!=nil{t.Fatal(err)}
    if err=InstallC1GovernedPendingOnExistingSoR(ctx,admin);err==nil{
        t.Fatal("second offline C1 governed install tried to overwrite the existing schema/roles")
    }
    if generations2,accepted2,e:=before();e!=nil||generations2!=1||accepted2!=1{
        t.Fatal("second offline C1 governed installation mutated canonical Accepted")
    }
    t.Log("PASS: fresh offline canonical 51-table database + existing Accepted preserved; forced DDL/role rollback, successful governed Pending publisher install and exact repeat refusal")
}

