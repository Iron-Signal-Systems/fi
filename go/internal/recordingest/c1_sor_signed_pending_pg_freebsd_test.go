//go:build freebsd && fi_c1_sor_dev && fi_c1_schema_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Native FreeBSD / disposable PostgreSQL 18 ONLY: a real signed, received,
// durable generation becomes actual Pending source metadata via the same
// transaction that the active C1 fi-sor Bootstrap uses. No live FI records,
// server, credentials, trust files or populated C220 database are accessed.
package recordingest

import (
    "bytes"
    "context"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/jackc/pgx/v5"
)

func c1TestSignedOriginalPendingPostgres18(t *testing.T,ctx context.Context,
    admin,worker *pgx.Conn) {
    t.Helper()
    if os.Getenv("GITHUB_ACTIONS")!="true"||
        os.Getenv("FI_C1_SCHEMA_CI_ALLOW_DISPOSABLE")!="1" {
        t.Fatal("STOP: real signed Pending SQL admission requires disposable CI authorization")
    }
    if admin==nil||worker==nil||admin==worker {
        t.Fatal("C1 signed pending requires separate fixture admin and worker SQL sessions")
    }
    root:=t.TempDir()
    source:="c1-signed-pending-fixture.iss.local"
    for _,name:=range []string{
        "custody","recorded","ready",
        filepath.Join("recorded","sources",source),
    }{
        if err:=os.MkdirAll(filepath.Join(root,name),0700);err!=nil{t.Fatal(err)}
    }
    signed:=m1WriteSignedGeneration(t,root,source)
    cfg:=c1NativeBCustodyConfig{
        CustodyRoot:filepath.Join(root,"custody"),
        RecordedRoot:filepath.Join(root,"recorded"),
        SourceNamespaces:true,
        MaxCanonicalBytes:64<<20,
        MaxEncodedBytes:64<<20,
        MaxManifestBytes:1<<20,
    }
    trust:=func(requested string)(generationTrustBundle,error){
        if requested!=source {
            return generationTrustBundle{},fmt.Errorf("C1 signed pending foreign trust %q",requested)
        }
        return signed.Trust,nil
    }
    original,err:=c1StreamOriginalSignedManifestPlanWithTrust(
        ctx,source,signed.GenerationID,cfg,trust)
    if err!=nil{t.Fatalf("C1 signed receiver original manifest: %v",err)}
    if original==nil||len(original.Batches)!=1{
        t.Fatal("C1 signed original receiver did not return exactly one recorded batch")
    }
    f:=c1handoff.Frame{
        Kind:c1handoff.Start,Sequence:1,SourceID:source,
        GenerationID:signed.GenerationID,ReceiptSHA256:original.ReceiptSHA256,
        ExpectedRecords:int64(original.Receipt.RecordCount),
        BatchIDs:[]string{original.Batches[0].BatchID},
    }
    if err=f.Validate();err!=nil{t.Fatal(err)}
    wrong:=f
    wrong.ReceiptSHA256=strings.Repeat("0",64)
    if e:=c1StageVerifiedPendingMetadata(ctx,worker,wrong,original);e==nil{
        t.Fatal("C1 signed Pending admitted an untrusted, wrong receipt before SQL")
    }
    swapped:=f
    swapped.BatchIDs=[]string{"foreign-batch"}
    if e:=c1StageVerifiedPendingMetadata(ctx,worker,swapped,original);e==nil{
        t.Fatal("C1 signed Pending admitted a foreign batch roster")
    }
    if err=c1StageVerifiedPendingMetadata(ctx,worker,f,original);err!=nil{
        t.Fatalf("C1 authenticated signed receiver generation failed real PostgreSQL18 Pending admission: %v",err)
    }
    var generations,batches,controls,sourceRows,canonicalRows,journalRows int64
    err=admin.QueryRow(ctx,`SELECT
        (SELECT count(*) FROM fi_c1_pending.recorded_generation),
        (SELECT count(*) FROM fi_c1_pending.source_batch),
        (SELECT count(*) FROM fi_c1_pending.generation_control),
        (SELECT count(*) FROM fi_c1_pending.source_record),
        (SELECT count(*) FROM fi.recorded_generation),
        (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')`).
        Scan(&generations,&batches,&controls,&sourceRows,&canonicalRows,&journalRows)
    if err!=nil{t.Fatal(err)}
    if generations!=1||batches!=1||controls!=1||sourceRows!=0||
        canonicalRows!=0||journalRows!=0 {
        t.Fatalf("C1 actual signed Pending metadata leaked or incomplete: generation=%d batches=%d controls=%d parents=%d canonical=%d accepted=%d",
            generations,batches,controls,sourceRows,canonicalRows,journalRows)
    }
    var sqlReceipt,sqlTransfer,sqlManifest,sqlData []byte
    var sqlRecords,sqlBytes int64
    var state string
    err=admin.QueryRow(ctx,`SELECT g.receipt_sha256,g.transfer_sha256,
        b.manifest_sha256,b.data_sha256,b.record_count,b.data_bytes,c.state
        FROM fi_c1_pending.recorded_generation g
        JOIN fi_c1_pending.source_batch b USING(recorded_generation_id)
        JOIN fi_c1_pending.generation_control c
          ON c.source_id=g.source_id AND c.generation_id=g.generation_id
        WHERE g.source_id=$1 AND g.generation_id=$2`,source,signed.GenerationID).
        Scan(&sqlReceipt,&sqlTransfer,&sqlManifest,&sqlData,&sqlRecords,&sqlBytes,&state)
    if err!=nil{t.Fatal(err)}
    receiptBytes,_:=decodeHex(original.ReceiptSHA256,32,true,"signed fixture receipt")
    transferBytes,_:=decodeHex(original.Receipt.TransferSHA256,32,true,"signed fixture transfer")
    manifestBytes,_:=decodeHex(original.Batches[0].ManifestSHA256,32,true,"signed fixture manifest")
    dataBytes,_:=decodeHex(original.Batches[0].Manifest.DataSHA256,32,true,"signed fixture data")
    if state!="Pending"||!bytes.Equal(sqlReceipt,receiptBytes)||
        !bytes.Equal(sqlTransfer,transferBytes)||
        !bytes.Equal(sqlManifest,manifestBytes)||
        !bytes.Equal(sqlData,dataBytes)||
        sqlRecords!=f.ExpectedRecords||sqlBytes!=original.Batches[0].Manifest.DataBytes {
        t.Fatal("C1 signed original receipt/transfer/manifest/data identity drift in committed Pending ledger")
    }
    if err=c1StageVerifiedPendingMetadata(ctx,worker,f,original);err==nil{
        t.Fatal("C1 signed Pending unexpectedly overwrote an unresolved generation on retry")
    }
    // Now use the *actual* C1 ordered SourceParent writer and its five-family
    // shared SQL pool on the immutable signed receiver record. This is not
    // synthetic INSERT SQL; it exercises the projector already used by fi-sor.
    var batchID int64
    if err=admin.QueryRow(ctx,`SELECT source_batch_id
        FROM fi_c1_pending.source_batch WHERE batch_id=$1`,
        original.Batches[0].BatchID).Scan(&batchID);err!=nil{
        t.Fatalf("C1 signed Pending SQL batch identity lookup: %v",err)
    }
    signedRaw,err:=os.ReadFile(filepath.Join(root,source,"frozen",
        original.Batches[0].DataArtifactName))
    if err!=nil{t.Fatal(err)}
    prepared,err:=PrepareSourceRecord(signedRaw)
    if err!=nil{t.Fatalf("C1 signed original record preparation: %v",err)}
    family,err:=privateP6KindFamily(prepared.Record.RecordKind)
    if err!=nil{t.Fatalf("C1 original signed record typed family: %v",err)}
    signedRecord:=privateP6Record{
        signedBatchIndex:0,sourceBatchID:batchID,ordinal:1,prepared:prepared,
    }
    opener:=func(ctx context.Context,_,_ string)(*pgx.Conn,int64,error){
        conn,e:=pgx.ConnectConfig(ctx,worker.Config().Copy())
        if e!=nil{return nil,0,e}
        var pid int64
        if e=conn.QueryRow(ctx,"SELECT pg_backend_pid()::bigint").Scan(&pid);e!=nil{
            _=conn.Close(context.Background())
            return nil,0,e
        }
        return conn,pid,nil
    }
    pool,err:=newC1SQLWithOpener(ctx,"","","c1-signed-pending",2,false,
        opener,false,c1GovernedPendingSchema)
    if err!=nil{t.Fatalf("C1 genuine signed 5-family SQL pool: %v",err)}
    if err=pool.Source(ctx,[]privateP6Record{signedRecord});err!=nil{
        pool.Close();t.Fatalf("C1 signed SourceParent SQL handoff: %v",err)
    }
    if err=pool.WaitSource(ctx);err!=nil{
        pool.Close();t.Fatalf("C1 signed SourceParent SQL COMMIT: %v",err)
    }
    if err=pool.Family(ctx,family,[]privateP6Record{signedRecord});err!=nil{
        pool.Close();t.Fatalf("C1 signed typed-family SQL handoff: %v",err)
    }
    if err=pool.WaitFamily(ctx,family);err!=nil{
        pool.Close();t.Fatalf("C1 signed typed-family SQL COMMIT: %v",err)
    }
    if err=pool.WaitAll(ctx);err!=nil{
        pool.Close();t.Fatalf("C1 signed 5-family SQL drain: %v",err)
    }
    pool.Close()
    auditor,err:=pgx.ConnectConfig(ctx,worker.Config().Copy())
    if err!=nil{t.Fatal(err)}
    defer auditor.Close(context.Background())
    if _,err=auditor.Exec(ctx,"SET default_transaction_read_only = on");err!=nil{
        t.Fatal(err)
    }
    if err=c1NativeBVerifyData(ctx,auditor,bytes.NewReader(signedRaw),
        0,batchID,original.Batches[0],c1GovernedPendingSchema);err!=nil{
        t.Fatalf("C1 separate readonly B original signed SourceParent/typed proof: %v",err)
    }
    var parentCount,canonicalParents int64
    if err=admin.QueryRow(ctx,`SELECT
        (SELECT count(*) FROM fi_c1_pending.source_record),
        (SELECT count(*) FROM fi.source_record)`).
        Scan(&parentCount,&canonicalParents);err!=nil{t.Fatal(err)}
    if parentCount!=1||canonicalParents!=0{
        t.Fatalf("C1 signed SQL writer escaped Pending or omitted SourceParent: pending=%d canonical=%d",
            parentCount,canonicalParents)
    }
    // SQL tampering must be detected from a separate session comparing
    // the unmodified original signed record. Restore only inside CI.
    if _,err=admin.Exec(ctx,`UPDATE fi_c1_pending.source_record
        SET record_sha256=$1`,bytes.Repeat([]byte{0x22},32));err!=nil{
        t.Fatal(err)
    }
    if e:=c1NativeBVerifyData(ctx,auditor,bytes.NewReader(signedRaw),
        0,batchID,original.Batches[0],c1GovernedPendingSchema);e==nil{
        t.Fatal("C1 independent B accepted modified committed SourceParent digest")
    }
    if _,err=admin.Exec(ctx,`UPDATE fi_c1_pending.source_record
        SET record_sha256=$1`,prepared.RecordDigest[:]);err!=nil{
        t.Fatal(err)
    }
    if err=c1NativeBVerifyData(ctx,auditor,bytes.NewReader(signedRaw),
        0,batchID,original.Batches[0],c1GovernedPendingSchema);err!=nil{
        t.Fatalf("C1 independent B did not recover after exact restored signed record: %v",err)
    }
    // This cleanup is permitted ONLY in the disposable, synthetic CI database.
    // No production path may clear unresolved original signed metadata.
    targets,err:=c1PendingRetireTables()
    if err!=nil{t.Fatal(err)}
    if _,err=admin.Exec(ctx,"TRUNCATE TABLE "+strings.Join(targets,", ")+
        " CONTINUE IDENTITY RESTRICT");err!=nil{
        t.Fatalf("C1 disposable signed fixture cleanup: %v",err)
    }
    t.Log("PASS: original receiver-signed custody -> immutable manifest -> exact Pending PostgreSQL18 metadata/control commit, duplicate and forgery rejected, canonical FI unchanged")
}
