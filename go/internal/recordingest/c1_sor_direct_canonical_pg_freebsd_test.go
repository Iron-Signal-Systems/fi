//go:build freebsd && fi_c1_sor_dev && fi_c1_schema_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Real signed receiver fixture, genuine FreeBSD PostgreSQL18, EXACT canonical
// SourceParent/family P6 COPY, real independent B child OS process and ONE
// journal-only Accepted. Runs only after all existing Pending integration
// tests, in disposable CI with its own cluster and no live C220 access.
package recordingest

import (
    "context"
    "fmt"
    "os"
    "path/filepath"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/jackc/pgx/v5"
)

func c1TestDirectCanonicalSignedPostgres18(t *testing.T,ctx context.Context,
    admin,worker,publisher *pgx.Conn){
    t.Helper()
    if os.Getenv("GITHUB_ACTIONS")!="true"||
       os.Getenv("FI_C1_SCHEMA_CI_ALLOW_DISPOSABLE")!="1"||
       admin==nil||worker==nil||publisher==nil{
        t.Fatal("C1 direct: disposable native FreeBSD PostgreSQL18 only")
    }
    var sid string
    if err:=admin.QueryRow(ctx,`SELECT current_database()||'|'||
        current_setting('data_directory')||'|'||
        (SELECT system_identifier FROM pg_control_system())::text`).Scan(&sid);err!=nil{
        t.Fatal(err)
    }
    if admin==worker||admin==publisher||worker==publisher{
        t.Fatal("C1 direct: distinct SQL administrator, worker and journal roles required")
    }
    // After previous Pending tests, perform the same narrow role cutover
    // planned for real C220. No shared canonical UPDATE, no worker journal.
    grants:=[]string{
        `GRANT USAGE ON SCHEMA fi TO fi_ingest,fi_c1_publisher`,
        `GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA fi TO fi_ingest`,
        `GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA fi TO fi_ingest`,
        `REVOKE UPDATE,DELETE,TRUNCATE,MAINTAIN ON ALL TABLES IN SCHEMA fi FROM fi_ingest`,
        `REVOKE INSERT ON fi.ingest_journal FROM fi_ingest`,
        `REVOKE INSERT ON ALL TABLES IN SCHEMA fi FROM fi_c1_publisher`,
        `GRANT SELECT,MAINTAIN ON ALL TABLES IN SCHEMA fi TO fi_c1_publisher`,
        `GRANT INSERT ON fi.ingest_journal TO fi_c1_publisher`,
    }
    for _,sql:=range grants{
        if _,err:=admin.Exec(ctx,sql);err!=nil{
            t.Fatalf("C1 direct disposable role cutover %q: %v",sql,err)
        }
    }
    workerDSN:=fmt.Sprintf("host=%s port=5432 dbname=fi user=fi_ingest password=isolated-only-test sslmode=disable",worker.Config().Host)
    publisherDSN:=fmt.Sprintf("host=%s port=5432 dbname=fi user=fi_c1_publisher password=isolated-only-test sslmode=disable",publisher.Config().Host)
    if err:=c1PreflightDirectCanonicalSQL(ctx,workerDSN);err!=nil{
        t.Fatalf("C1 direct role preflight on real disposable canonical SQL: %v",err)
    }
    root:=t.TempDir()
    source:="c1-direct-signed-fixture.iss.local"
    for _,name:=range []string{
        "custody","recorded","ready",
        filepath.Join("recorded","sources",source),
    } {
        if err:=os.MkdirAll(filepath.Join(root,name),0700);err!=nil{t.Fatal(err)}
    }
    signed:=m1WriteSignedGeneration(t,root,source)
    custody:=c1NativeBCustodyConfig{
        CustodyRoot:filepath.Join(root,"custody"),
        RecordedRoot:filepath.Join(root,"recorded"),SourceNamespaces:true,
        MaxCanonicalBytes:64<<20,MaxEncodedBytes:64<<20,
        MaxManifestBytes:1<<20,
    }
    trust:=func(requested string)(generationTrustBundle,error){
        if requested!=source{return generationTrustBundle{},fmt.Errorf("C1 direct: foreign signed source %s",requested)}
        return signed.Trust,nil
    }
    original,err:=c1StreamOriginalSignedManifestPlanWithTrust(
        ctx,source,signed.GenerationID,custody,trust)
    if err!=nil{t.Fatalf("C1 direct original signed receipt: %v",err)}
    if len(original.Batches)!=1||original.Receipt.RecordCount!=1{
        t.Fatal("C1 direct: malformed signed one-batch fixture")
    }
    batch:=original.Batches[0]
    start:=c1handoff.Frame{
        Kind:c1handoff.Start,Sequence:1,SourceID:source,
        GenerationID:signed.GenerationID,ReceiptSHA256:original.ReceiptSHA256,
        ExpectedRecords:1,BatchIDs:[]string{batch.BatchID},
    }
    if err=start.Validate();err!=nil{t.Fatal(err)}

    var historical int64
    if err=admin.QueryRow(ctx,`SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'`).
        Scan(&historical);err!=nil{t.Fatal(err)}
    // The production bootstrap uses the same original insertRecordedGeneration
    // and bounded source_batch COPY. All direct typed workers reuse P6.
    ledger,err:=worker.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.ReadCommitted})
    if err!=nil{t.Fatal(err)}
    ids,err:=c1StageOriginalCanonicalLedgerTx(ctx,ledger,original)
    if err!=nil{_ =ledger.Rollback(context.Background());t.Fatalf("C1 signed canonical ledger: %v",err)}
    if len(ids)!=1||ids[0]<=0{t.Fatal("C1 signed ledger returned invalid source batch identity")}
    if err=ledger.Commit(ctx);err!=nil{t.Fatal(err)}
    raw,err:=os.ReadFile(filepath.Join(root,source,"frozen",batch.DataArtifactName))
    if err!=nil{t.Fatal(err)}
    prepared,err:=PrepareSourceRecord(raw)
    if err!=nil{t.Fatal(err)}
    family,err:=privateP6KindFamily(prepared.Record.RecordKind)
    if err!=nil{t.Fatal(err)}
    record:=privateP6Record{
        signedBatchIndex:0,sourceBatchID:ids[0],ordinal:1,prepared:prepared,
    }
    opener:=func(ctx context.Context,_,_ string)(*pgx.Conn,int64,error){
        conn,err:=pgx.ConnectConfig(ctx,worker.Config().Copy())
        if err!=nil{return nil,0,err}
        var pid int64
        if err=conn.QueryRow(ctx,"SELECT pg_backend_pid()::bigint").Scan(&pid);err!=nil{
            _=conn.Close(context.Background());return nil,0,err
        }
        return conn,pid,nil
    }
    pool,err:=newC1SQLWithOpener(ctx,"","",source,2,false,opener,false,"fi")
    if err!=nil{t.Fatalf("C1 direct original P6 SQL pool: %v",err)}
    if err=pool.Source(ctx,[]privateP6Record{record});err!=nil{
        pool.Close();t.Fatalf("C1 direct ordered SourceParent: %v",err)
    }
    if err=pool.WaitSource(ctx);err!=nil{
        pool.Close();t.Fatalf("C1 direct SourceParent COMMIT: %v",err)
    }
    if err=pool.Family(ctx,family,[]privateP6Record{record});err!=nil{
        pool.Close();t.Fatalf("C1 direct typed family: %v",err)
    }
    if err=pool.WaitFamily(ctx,family);err!=nil{
        pool.Close();t.Fatalf("C1 direct typed-family COMMIT: %v",err)
    }
    if err=pool.WaitAll(ctx);err!=nil{
        pool.Close();t.Fatalf("C1 direct original P6 SQL drain: %v",err)
    }
    pool.Close()
    var persisted,accepted int64
    if err=admin.QueryRow(ctx,`SELECT
        (SELECT count(*) FROM fi.source_record r JOIN fi.source_batch b USING(source_batch_id)
         JOIN fi.recorded_generation g USING(recorded_generation_id)
         WHERE g.source_id=$1 AND g.generation_id=$2),
        (SELECT count(*) FROM fi.ingest_journal WHERE source_id=$1 AND generation_id=$2 AND outcome='Accepted')`,
        source,signed.GenerationID).Scan(&persisted,&accepted);err!=nil{t.Fatal(err)}
    if persisted!=1||accepted!=0{
        t.Fatalf("C1 direct: committed canonical record unavailable before B or accepted early: source=%d accepted=%d",persisted,accepted)
    }
    transfer:=original.Receipt.TransferSHA256
    descriptors:=[]BacklogCheckpointDescriptor{
        {SourceID:source,GenerationID:signed.GenerationID,
            ReceiptSHA256:original.ReceiptSHA256,TransferSHA256:transfer,
            EndBatch:0,EndRecord:0},
        {SourceID:source,GenerationID:signed.GenerationID,
            ReceiptSHA256:original.ReceiptSHA256,TransferSHA256:transfer,
            StartBatch:0,EndBatch:1,StartRecord:0,EndRecord:1,
            DataBytes:uint64(batch.Manifest.DataBytes)},
    }
    plan:=c1NativeBPlan{
        Start:start,SQLIDs:ids,Batches:original.Batches,
        Descriptors:descriptors,Transfer:transfer,SQLSchema:"fi",
    }
    // The original signed row is independently replay-verified in an
    // entirely separate FreeBSD test OS process against real canonical SQL.
    // The parent exercises actual READY -> B PASS -> FINAL PASS IPC.
    proof:=c1TestNativeBReadyProtocol(t,ctx,admin,plan,custody,signed.Trust)
    drain:=c1handoff.Frame{
        Kind:c1handoff.Drain,Sequence:2,SourceID:source,
        GenerationID:signed.GenerationID,ReceiptSHA256:original.ReceiptSHA256,
    }
    if err=drain.Validate();err!=nil{t.Fatal(err)}
    if err=c1DirectWriteAccepted(ctx,publisherDSN,drain,1,1,proof);err!=nil{
        t.Fatalf("C1 direct: B-gated journal-only Accepted: %v",err)
    }
    if err=c1DirectWriteAccepted(ctx,publisherDSN,drain,1,1,proof);err==nil{
        t.Fatal("C1 direct: duplicate Accepted journal was written")
    }
    state,err:=c1ReadCanonicalAcceptanceAfterB(ctx,workerDSN,
        source,signed.GenerationID,original.ReceiptSHA256)
    if err!=nil||state!=c1handoff.FinalAccepted{
        t.Fatalf("C1 direct fresh canonical Accepted readback: %d %v",state,err)
    }
    var canonicalRows,acceptedRows,after int64
    if err=admin.QueryRow(ctx,`SELECT
        (SELECT count(*) FROM fi.source_record r JOIN fi.source_batch b USING(source_batch_id)
         JOIN fi.recorded_generation g USING(recorded_generation_id)
         WHERE g.source_id=$1 AND g.generation_id=$2),
        (SELECT count(*) FROM fi.ingest_journal j
         WHERE j.source_id=$1 AND j.generation_id=$2 AND j.outcome='Accepted'),
        (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')`,
        source,signed.GenerationID).Scan(&canonicalRows,&acceptedRows,&after);err!=nil{t.Fatal(err)}
    if canonicalRows!=1||acceptedRows!=1||after!=historical+1{
        t.Fatalf("C1 direct canonical changed history or duplicated source rows: source=%d accepted=%d historical=%d after=%d",canonicalRows,acceptedRows,historical,after)
    }
    t.Logf("PASS: original receiver-signed custody -> original direct canonical P6 SourceParent/family -> distinct process B -> ONE Accepted journal without 49-table republish; preserved prior %d Accepted; fixture system=%s",historical,sid)
}
