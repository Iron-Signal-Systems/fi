//go:build fi_c1_sor_dev && fi_c1_schema_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// DISPOSABLE PostgreSQL18 ONLY. This tests the *relational remapping*
// transaction with a synthetic SQL fixture and a test-only proof callback.
// It does NOT claim end-to-end original signed custody verification B.
package recordingest

import (
    "context"
    "encoding/hex"
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/jackc/pgx/v5"
)

func c1TestPendingRelationalPromotionPostgres18(t *testing.T,ctx context.Context,
    admin,publisher *pgx.Conn){
    t.Helper()
    if admin==nil||publisher==nil||admin==publisher{
        t.Fatal("C1 pending remapper fixture needs two isolated PostgreSQL sessions")
    }
    source,generation:="ci-pending-remap-source","ci-pending-remap-generation"
    receipt:=strings.Repeat("4",64)
    transfer:=strings.Repeat("7",64)
    d,_:=hex.DecodeString(receipt)
    x,_:=hex.DecodeString(transfer)
    hash:=[]byte(strings.Repeat("x",32))
    var gid,bid int64
    err:=admin.QueryRow(ctx,`INSERT INTO fi_c1_pending.recorded_generation(
        receipt_version,descriptor_version,source_id,generation_id,
        canonical_version,data_encoding,artifact_count,source_bytes,
        canonical_bytes,canonical_sha256,encoded_data_bytes,encoded_data_sha256,
        metadata_bytes,metadata_sha256,transfer_bytes,transfer_sha256,
        batch_count,data_bytes,record_count,receipt_bytes,receipt_sha256,ingest_version)
        VALUES ('ci','ci',$1,$2,'ci','none',2,128,128,$3,64,$3,
                32,$3,116,$4,1,128,1,120,$5,'ci-only')
        RETURNING recorded_generation_id`,source,generation,hash,x,d).Scan(&gid)
    if err!=nil{t.Fatalf("C1 pending synthetic recorded generation: %v",err)}
    err=admin.QueryRow(ctx,`INSERT INTO fi_c1_pending.source_batch(
        recorded_generation_id,manifest_artifact_name,data_artifact_name,
        manifest_version,batch_id,target_batch_size,record_count,data_bytes,
        data_sha256,data_file,collector_executable_path,collector_executable_sha256,
        created_at,completed_at,manifest_bytes,manifest_sha256)
        VALUES ($1,'batch-000001.manifest.json','batch-000001.jsonl',
               'ci','batch-000001',1,1,128,$2,'batch-000001.jsonl',
               '/ci/collector',$2,clock_timestamp(),clock_timestamp(),128,$2)
        RETURNING source_batch_id`,gid,hash).Scan(&bid)
    if err!=nil{t.Fatalf("C1 pending synthetic batch: %v",err)}
    if _,err=admin.Exec(ctx,`INSERT INTO fi_c1_pending.source_record(
        source_batch_id,record_ordinal,version,record_kind,scope_id,
        written_at,record_bytes,record_sha256,ingest_version)
        VALUES($1,1,'ci','CI-SyntheticRemapOnly','ci',
               clock_timestamp(),128,$2,'ci-only')`,bid,hash);err!=nil{
        t.Fatalf("C1 pending synthetic SourceParent: %v",err)
    }
    if _,err=admin.Exec(ctx,`INSERT INTO fi_c1_pending.generation_control(
        source_id,generation_id,receipt_sha256,transfer_sha256,
        record_count,batch_count)
        SELECT source_id,generation_id,receipt_sha256,transfer_sha256,
               record_count,batch_count
        FROM fi_c1_pending.recorded_generation WHERE recorded_generation_id=$1`,gid);err!=nil{
        t.Fatalf("C1 pending synthetic control: %v",err)
    }
    g:=&PreparedGeneration{ReceiptSHA256:receipt,
        Batches:[]PreparedBatch{{BatchID:"batch-000001"}}}
    g.Receipt.Descriptor.SourceID=source
    g.Receipt.Descriptor.GenerationID=generation
    g.Receipt.TransferSHA256=transfer
    g.Receipt.RecordCount=1
    g.Receipt.BatchCount=1
    g.Receipt.DataBytes=128
    // Explicit test-only injected proof; genuine B MUST independently
    // verify original signed custody and every typed root before publication.
    proof:=func(_ context.Context,_ *pgx.Conn,_ *PreparedGeneration,
        _ BacklogWindowLimits)(BacklogGenerationVerification,error){
        return BacklogGenerationVerification{SourceID:source,GenerationID:generation,
            ReceiptSHA256:receipt,Records:1,DataBytes:128},nil
    }
    // Retirement before canonical Accepted is FORBIDDEN. Its rejected
    // transaction must preserve all original pending SourceParent rows.
    negativeRetire,negErr:=publisher.Begin(ctx)
    if negErr!=nil{t.Fatal(negErr)}
    negErr=c1RetireAcceptedPendingTx(ctx,negativeRetire,source,generation,receipt)
    _=negativeRetire.Rollback(context.Background())
    if negErr==nil{t.Fatal("C1 retired unaccepted pending generation")}
    if _,err=admin.Exec(ctx,`ALTER TABLE fi.source_record ADD CONSTRAINT
        ci_pending_forced_rollback CHECK (false) NOT VALID`);err!=nil{t.Fatal(err)}
    if _,err=promoteVerifiedBacklogToPopulatedSoRWithProofSchema(ctx,admin,publisher,
        g,BacklogWindowLimits{},"ci-pending-forced-rollback",proof,
        c1GovernedPendingSchema);err==nil{
        t.Fatal("C1 pending remap committed despite late canonical CHECK failure")
    }
    if _,err=admin.Exec(ctx,`ALTER TABLE fi.source_record
        DROP CONSTRAINT ci_pending_forced_rollback`);err!=nil{t.Fatal(err)}
    var before,accepted int64
    if err=admin.QueryRow(ctx,`SELECT
        (SELECT count(*) FROM fi.source_record),
        (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')`).
        Scan(&before,&accepted);err!=nil{t.Fatal(err)}
    if before!=0||accepted!=0{
        t.Fatal("C1 pending failed transaction left canonical rows or Accepted journal")
    }
    published,err:=promoteVerifiedBacklogToPopulatedSoRWithProofSchema(ctx,admin,publisher,
        g,BacklogWindowLimits{},"ci-pending-atomic-acceptance",proof,
        c1GovernedPendingSchema)
    if err!=nil{t.Fatalf("C1 pending canonical remapper failed: %v",err)}
    if published.Outcome!="Accepted"||published.RecordsCommitted!=1{
        t.Fatalf("C1 pending result not canonical Accepted: %+v",published)
    }
    tx,err:=admin.BeginTx(ctx,pgx.TxOptions{AccessMode:pgx.ReadOnly,
        IsoLevel:pgx.RepeatableRead})
    if err!=nil{t.Fatal(err)}
    state,err:=c1CanonicalStatusInSnapshot(ctx,tx,source,generation,receipt)
    if err!=nil||state!=c1handoff.FinalAccepted{
        _=tx.Rollback(context.Background())
        t.Fatalf("C1 pending canonical readback failed: %v %v",state,err)
    }
    if err=tx.Commit(ctx);err!=nil{t.Fatal(err)}
    again,err:=promoteVerifiedBacklogToPopulatedSoRWithProofSchema(ctx,admin,publisher,
        g,BacklogWindowLimits{},"ci-pending-exact-retry",proof,
        c1GovernedPendingSchema)
    if err!=nil||again.Outcome!="AlreadyAccepted"{
        t.Fatalf("C1 pending exact already-Accepted retry failed: %+v %v",again,err)
    }
    var nrecords,naccepted int64
    if err=admin.QueryRow(ctx,`SELECT
        (SELECT count(*) FROM fi.source_record),
        (SELECT count(*) FROM fi.ingest_journal
         WHERE source_id=$1 AND generation_id=$2 AND outcome='Accepted')`,
        source,generation).Scan(&nrecords,&naccepted);err!=nil{t.Fatal(err)}
    if nrecords!=1||naccepted!=1{
        t.Fatalf("C1 pending canonical duplicate after retry source=%d accepted=%d",nrecords,naccepted)
    }
    // Wrong custody digest can never retire the verified pending SQL rows.
    wrongTx,e:=publisher.Begin(ctx)
    if e!=nil{t.Fatal(e)}
    wrongErr:=c1RetireAcceptedPendingTx(ctx,wrongTx,source,generation,strings.Repeat("8",64))
    _=wrongTx.Rollback(context.Background())
    if wrongErr==nil{t.Fatal("C1 pending retirement accepted wrong signed receipt")}
    // An extra foreign control/recorded generation must fail closed.
    foreignTx,e:=admin.Begin(ctx)
    if e!=nil{t.Fatal(e)}
    if _,e=foreignTx.Exec(ctx,`INSERT INTO fi_c1_pending.recorded_generation(
        receipt_version,descriptor_version,source_id,generation_id,
        canonical_version,data_encoding,artifact_count,source_bytes,
        canonical_bytes,canonical_sha256,encoded_data_bytes,encoded_data_sha256,
        metadata_bytes,metadata_sha256,transfer_bytes,transfer_sha256,
        batch_count,data_bytes,record_count,receipt_bytes,receipt_sha256,ingest_version)
        VALUES ('ci','ci','foreign-ci','foreign-gen','ci','none',2,128,128,
          decode(repeat('33',32),'hex'),64,decode(repeat('33',32),'hex'),
          32,decode(repeat('33',32),'hex'),116,decode(repeat('33',32),'hex'),
          1,128,1,120,decode(repeat('33',32),'hex'),'ci-only')`);e!=nil{t.Fatal(e)}
    if e=foreignTx.Commit(ctx);e!=nil{t.Fatal(e)}
    foreignRetire,e:=publisher.Begin(ctx)
    if e!=nil{t.Fatal(e)}
    foreignErr:=c1RetireAcceptedPendingTx(ctx,foreignRetire,source,generation,receipt)
    _=foreignRetire.Rollback(context.Background())
    if foreignErr==nil{t.Fatal("C1 retired unrelated pending source")}
    if _,e=admin.Exec(ctx,`DELETE FROM fi_c1_pending.recorded_generation
       WHERE source_id='foreign-ci' AND generation_id='foreign-gen'`);e!=nil{t.Fatal(e)}
    // Only a verified canonical Accepted may authorize this one atomic
    // pending retirement. Canonical FI and original custody are untouched.
    retire,e:=publisher.Begin(ctx)
    if e!=nil{t.Fatal(e)}
    if e=c1RetireAcceptedPendingTx(ctx,retire,source,generation,receipt);e!=nil{
        _=retire.Rollback(context.Background())
        t.Fatalf("C1 canonical Accepted failed pending retirement: %v",e)
    }
    if e=retire.Commit(ctx);e!=nil{t.Fatal(e)}
    var pendingRows int64
    if e=admin.QueryRow(ctx,`SELECT
      (SELECT count(*) FROM fi_c1_pending.source_record)+
      (SELECT count(*) FROM fi_c1_pending.recorded_generation)+
      (SELECT count(*) FROM fi_c1_pending.generation_control)`).Scan(&pendingRows);e!=nil{t.Fatal(e)}
    if pendingRows!=0{t.Fatalf("C1 pending post-Accepted retirement left rows: %d",pendingRows)}
    // Idempotent recovery after ambiguous cleanup commit must not damage
    // the already accepted canonical generation or its journal.
    retryRetire,e:=publisher.Begin(ctx)
    if e!=nil{t.Fatal(e)}
    if e=c1RetireAcceptedPendingTx(ctx,retryRetire,source,generation,receipt);e!=nil{
        _=retryRetire.Rollback(context.Background())
        t.Fatalf("C1 retirement ambiguous-commit retry blocked: %v",e)
    }
    if e=retryRetire.Commit(ctx);e!=nil{t.Fatal(e)}
    if e=admin.QueryRow(ctx,`SELECT count(*) FROM fi.ingest_journal WHERE
       source_id=$1 AND generation_id=$2 AND outcome='Accepted'`,
       source,generation).Scan(&naccepted);e!=nil{t.Fatal(e)}
    if naccepted!=1{t.Fatal("C1 retirement destroyed or duplicated canonical Accepted")}
}
