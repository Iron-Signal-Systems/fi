//go:build freebsd && fi_c1_sor_dev && fi_c1_schema_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Disposable native FreeBSD/PostgreSQL18: restart the ORIGINAL native C1
// shared SQL pool after SourceParent COMMIT but before the typed projection.
// Never infer durable rows from RAM, original handoff ACK or transport state.
// Replay the exact signed original through the existing fi-sor EnqueueReplay.
// This is a worker restart simulation, NOT a full PG18 crash/powercut test.
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

func c1TestSignedInterruptedPendingReplayPG18(t *testing.T,ctx context.Context,
    admin,worker *pgx.Conn) {
    t.Helper()
    if os.Getenv("GITHUB_ACTIONS")!="true"||
        os.Getenv("FI_C1_SCHEMA_CI_ALLOW_DISPOSABLE")!="1"{
        t.Fatal("STOP: original signed replay requires isolated native FreeBSD PostgreSQL18")
    }
    root:=t.TempDir()
    source:="c1-signed-restart-fixture.iss.local"
    for _,dir:=range []string{"custody","recorded","ready",
        filepath.Join("recorded","sources",source)}{
        if err:=os.MkdirAll(filepath.Join(root,dir),0700);err!=nil{t.Fatal(err)}
    }
    signed:=m1WriteSignedGeneration(t,root,source)
    custody:=c1NativeBCustodyConfig{
        CustodyRoot:filepath.Join(root,"custody"),
        RecordedRoot:filepath.Join(root,"recorded"),
        SourceNamespaces:true,MaxCanonicalBytes:64<<20,
        MaxEncodedBytes:64<<20,MaxManifestBytes:1<<20,
    }
    trust:=func(want string)(generationTrustBundle,error){
        if want!=source{return generationTrustBundle{},fmt.Errorf("foreign signed replay source %s",want)}
        return signed.Trust,nil
    }
    original,err:=c1StreamOriginalSignedManifestPlanWithTrust(ctx,source,
        signed.GenerationID,custody,trust)
    if err!=nil{t.Fatal(err)}
    if len(original.Batches)!=1||original.Receipt.RecordCount!=1{
        t.Fatal("signed replay fixture requires exactly one immutable batch and record")
    }
    start:=c1handoff.Frame{
        Kind:c1handoff.Start,Sequence:1,SourceID:source,
        GenerationID:signed.GenerationID,ReceiptSHA256:original.ReceiptSHA256,
        ExpectedRecords:1,BatchIDs:[]string{original.Batches[0].BatchID},
    }
    if err=c1StageVerifiedPendingMetadata(ctx,worker,start,original);err!=nil{t.Fatal(err)}
    var batch int64
    if err=admin.QueryRow(ctx,`SELECT source_batch_id
        FROM fi_c1_pending.source_batch WHERE batch_id=$1`,
        original.Batches[0].BatchID).Scan(&batch);err!=nil{t.Fatal(err)}
    raw,err:=os.ReadFile(filepath.Join(root,source,"frozen",
        original.Batches[0].DataArtifactName))
    if err!=nil{t.Fatal(err)}
    prepared,err:=PrepareSourceRecord(raw)
    if err!=nil{t.Fatal(err)}
    family,err:=privateP6KindFamily(prepared.Record.RecordKind)
    if err!=nil{t.Fatal(err)}
    row:=privateP6Record{signedBatchIndex:0,sourceBatchID:batch,
        ordinal:1,prepared:prepared}
    opener:=func(ctx context.Context,_,_ string)(*pgx.Conn,int64,error){
        c,e:=pgx.ConnectConfig(ctx,worker.Config().Copy())
        if e!=nil{return nil,0,e}
        var pid int64
        if e=c.QueryRow(ctx,"SELECT pg_backend_pid()::bigint").Scan(&pid);e!=nil{
            _=c.Close(context.Background());return nil,0,e
        }
        return c,pid,nil
    }
    // PRE-RESTART: one authentic ordered parent SQL transaction commits,
    // but the typed family is deliberately not submitted.
    first,err:=newC1SQLWithOpener(ctx,"","",source,2,false,opener,
        false,c1GovernedPendingSchema)
    if err!=nil{t.Fatal(err)}
    if err=first.Source(ctx,[]privateP6Record{row});err!=nil{first.Close();t.Fatal(err)}
    if err=first.WaitSource(ctx);err!=nil{first.Close();t.Fatal(err)}
    first.Close()

    read,err:=pgx.ConnectConfig(ctx,worker.Config().Copy())
    if err!=nil{t.Fatal(err)}
    defer read.Close(context.Background())
    if _,err=read.Exec(ctx,"SET default_transaction_read_only = on");err!=nil{t.Fatal(err)}
    inspect:=func()([]C1RecoveryRowState,error){
        tx,e:=read.BeginTx(ctx,pgx.TxOptions{
            IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly,
        })
        if e!=nil{return nil,e}
        defer tx.Rollback(context.Background())
        states,e:=c1AuditCommittedRowStates(ctx,tx,
            []privateP6Record{row},c1GovernedPendingSchema)
        if e!=nil{return nil,e}
        return states,tx.Commit(ctx)
    }
    states,err:=inspect()
    if err!=nil||len(states)!=1||!states[0].ParentCommitted||states[0].TypedRootCommitted{
        t.Fatalf("signed replay lost or fabricated pre-restart SQL state: %+v %v",states,err)
    }
    if err=c1NativeBVerifyData(ctx,read,bytes.NewReader(raw),0,batch,
        original.Batches[0],c1GovernedPendingSchema);err==nil{
        t.Fatal("independent B accepted a signed generation missing its typed SQL root")
    }

    // POST-RESTART: use the EXACT production EnqueueReplay path. The
    // separately read back original signed parent earns only virtual durable
    // parent credit; it is NOT written a second time. The missing typed root
    // must go through the real five-family PostgreSQL SQL worker.
    second,err:=newC1SQLWithOpener(ctx,"","",source,2,false,opener,
        false,c1GovernedPendingSchema)
    if err!=nil{t.Fatal(err)}
    defer second.Close()
    groups,err:=c1SoRGroupPlan(original.Batches,0)
    if err!=nil{t.Fatal(err)}
    tracker,err:=c1SoRCommitTracker(groups)
    if err!=nil{t.Fatal(err)}
    second.commitReady=tracker
    handler,err:=newC1SoRCommitHandler(second,source,signed.GenerationID,
        original.ReceiptSHA256,[]int64{batch},[]int64{1},1)
    if err!=nil{t.Fatal(err)}
    signedRow:=c1handoff.Row{SignedBatchIndex:0,SourceBatchID:batch,
        Ordinal:1,Digest:prepared.RecordDigest,RawRecord:raw}
    makeFrame:=func(kind c1handoff.Kind,seq uint64)c1handoff.Frame{
        return c1handoff.Frame{
            Kind:kind,Sequence:seq,SourceID:source,
            GenerationID:signed.GenerationID,ReceiptSHA256:original.ReceiptSHA256,
            Rows:[]c1handoff.Row{signedRow},
        }
    }
    parentF:=makeFrame(c1handoff.Source,2)
    future,err:=handler.EnqueueReplay(ctx,parentF,read)
    if err!=nil{t.Fatalf("governed signed source replay credit: %v",err)}
    if e,ok:=<-future;!ok||e!=nil{t.Fatalf("signed parent durable replay future: %v ok=%t",e,ok)}
    if second.parentRows!=1||len(second.sourceOutstanding)!=0{
        t.Fatal("C1 replay reinserted a previously committed signed SourceParent")
    }
    if err=tracker.Seal(1);err!=nil{t.Fatal(err)}
    typedF:=makeFrame(c1handoff.Kind(family+2),3)
    typedFuture,err:=handler.EnqueueReplay(ctx,typedF,read)
    if err!=nil{t.Fatalf("signed typed family recovery: %v",err)}
    if e,ok:=<-typedFuture;!ok||e!=nil{t.Fatalf("recovered typed SQL transaction: %v ok=%t",e,ok)}
    if err=second.WaitAll(ctx);err!=nil{t.Fatal(err)}
    if err=tracker.FinishCommitted();err!=nil{
        t.Fatalf("C1 B commit-ready proof after genuine signed restart: %v",err)
    }
    states,err=inspect()
    if err!=nil||len(states)!=1||!states[0].ParentCommitted||!states[0].TypedRootCommitted{
        t.Fatalf("signed replay could not prove both committed parent and typed root: %+v %v",states,err)
    }
    if err=c1NativeBVerifyData(ctx,read,bytes.NewReader(raw),0,batch,
        original.Batches[0],c1GovernedPendingSchema);err!=nil{
        t.Fatalf("C1 B rejected genuine signed record after exact missing SQL repair: %v",err)
    }
    var parents,typed,accepted int64
    if err=admin.QueryRow(ctx,`SELECT
        (SELECT count(*) FROM fi_c1_pending.source_record),
        (SELECT count(*) FROM fi_c1_pending.supporting_source_collection_error),
        (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'
         AND source_id=$1 AND generation_id=$2)`,
        source,signed.GenerationID).Scan(&parents,&typed,&accepted);err!=nil{t.Fatal(err)}
    if parents!=1||typed!=1||accepted!=0{
        t.Fatalf("C1 signed restart duplicated source or fabricated acceptance: parent=%d typed=%d accepted=%d",
            parents,typed,accepted)
    }
    targets,err:=c1PendingRetireTables()
    if err!=nil{t.Fatal(err)}
    if _,err=admin.Exec(ctx,"TRUNCATE TABLE "+strings.Join(targets,", ")+
        " CONTINUE IDENTITY RESTRICT");err!=nil{t.Fatal(err)}
    t.Log("PASS: real signed SourceParent commit -> SQL worker restart -> read-only parent proof -> typed SQL-only recovery -> B signed custody success, no duplicate parent/Accepted")
}
