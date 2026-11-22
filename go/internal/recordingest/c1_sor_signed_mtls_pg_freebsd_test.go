//go:build freebsd && fi_c1_sor_dev && fi_c1_schema_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// NATIVE FREEBSD DISPOSABLE PostgreSQL18 ONLY. Real original receiver-signed
// custody -> TLS1.3 mTLS -> prepared RAM -> existing C1 SourceParent/five-family
// SQL -> separate READ ONLY B full custody proof. This fixture runs both TLS
// endpoints in one isolated CI process, so it is NOT two physical jails and
// NOT a production B child or canonical Accepted publication test.
package recordingest

import (
    "context"
    "crypto/tls"
    "errors"
    "fmt"
    "net"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/jackc/pgx/v5"
)

func c1TestSignedMTLSRAMPostgres18(t *testing.T,ctx context.Context,
    admin,worker *pgx.Conn){
    t.Helper()
    if os.Getenv("GITHUB_ACTIONS")!="true"||
        os.Getenv("FI_C1_SCHEMA_CI_ALLOW_DISPOSABLE")!="1"{
        t.Fatal("STOP: signed SQL handoff allowed only in disposable FreeBSD CI")
    }
    if admin==nil||worker==nil||admin==worker{
        t.Fatal("C1 signed RAM SQL requires distinct administrative and worker identities")
    }
    root:=t.TempDir()
    source:="c1-signed-mtls-fixture.iss.local"
    for _,dir:=range []string{"custody","recorded","ready",
        filepath.Join("recorded","sources",source)} {
        if e:=os.MkdirAll(filepath.Join(root,dir),0700);e!=nil{t.Fatal(e)}
    }
    signed:=m1WriteSignedGeneration(t,root,source)
    custody:=c1NativeBCustodyConfig{
        CustodyRoot:filepath.Join(root,"custody"),
        RecordedRoot:filepath.Join(root,"recorded"),
        SourceNamespaces:true,MaxCanonicalBytes:64<<20,
        MaxEncodedBytes:64<<20,MaxManifestBytes:1<<20,
    }
    trust:=func(asked string)(generationTrustBundle,error){
        if asked!=source{return generationTrustBundle{},fmt.Errorf("C1 foreign signed trust %s",asked)}
        return signed.Trust,nil
    }
    original,e:=c1StreamOriginalSignedManifestPlanWithTrust(ctx,
        source,signed.GenerationID,custody,trust)
    if e!=nil{t.Fatal(e)}
    if len(original.Batches)!=1||original.Receipt.RecordCount!=1{
        t.Fatal("C1 mTLS fixture original signed batch cardinality changed")
    }
    start:=c1handoff.Frame{
        Kind:c1handoff.Start,Sequence:1,SourceID:source,
        GenerationID:signed.GenerationID,ReceiptSHA256:original.ReceiptSHA256,
        ExpectedRecords:int64(original.Receipt.RecordCount),
        BatchIDs:[]string{original.Batches[0].BatchID},
    }
    if e=start.Validate();e!=nil{t.Fatal(e)}
    // Admission is the exact production fi-sor PostgreSQL transaction,
    // but the trust resolver is injected only in this signed fixture.
    if e=c1StageVerifiedPendingMetadata(ctx,worker,start,original);e!=nil{
        t.Fatalf("C1 authentic signed mTLS Pending bootstrap: %v",e)
    }
    var batchID int64
    if e=admin.QueryRow(ctx,`SELECT source_batch_id FROM fi_c1_pending.source_batch
        WHERE batch_id=$1`,start.BatchIDs[0]).Scan(&batchID);e!=nil{t.Fatal(e)}
    raw,e:=os.ReadFile(filepath.Join(root,source,"frozen",
        original.Batches[0].DataArtifactName))
    if e!=nil{t.Fatal(e)}
    prepared,e:=PrepareSourceRecord(raw)
    if e!=nil{t.Fatal(e)}
    family,e:=privateP6KindFamily(prepared.Record.RecordKind)
    if e!=nil{t.Fatal(e)}
    signedRow:=privateP6Record{
        signedBatchIndex:0,sourceBatchID:batchID,ordinal:1,prepared:prepared,
    }
    opener:=func(ctx context.Context,_,_ string)(*pgx.Conn,int64,error){
        conn,err:=pgx.ConnectConfig(ctx,worker.Config().Copy())
        if err!=nil{return nil,0,err}
        var pid int64
        if err=conn.QueryRow(ctx,"SELECT pg_backend_pid()::bigint").Scan(&pid);err!=nil{
            _=conn.Close(context.Background())
            return nil,0,err
        }
        return conn,pid,nil
    }
    pool,e:=newC1SQLWithOpener(ctx,"","",source,2,false,opener,
        false,c1GovernedPendingSchema)
    if e!=nil{t.Fatal(e)}
    defer pool.Close()
    h,e:=newC1SoRCommitHandler(pool,source,signed.GenerationID,
        original.ReceiptSHA256,[]int64{batchID},
        []int64{int64(original.Receipt.RecordCount)},int64(original.Receipt.RecordCount))
    if e!=nil{t.Fatal(e)}
    store:=c1RAMTestStore(t)
    h.sharedRAM=store

    serverFiles,clientFiles:=issueC1MTLSRAMTestIdentity(t)
    serverTLS,e:=c1handoff.ServerTLSConfig(serverFiles,"fi-ingest.local")
    if e!=nil{t.Fatal(e)}
    clientTLS,e:=c1handoff.ClientTLSConfig(clientFiles,"fi-sor.local")
    if e!=nil{t.Fatal(e)}
    clientHalf,serverHalf:=net.Pipe()
    defer clientHalf.Close()
    defer serverHalf.Close()
    finished:=make(chan error,1)
    srv:=&c1handoff.Server{
        IOTimeout:20*time.Second,
        Bootstrap:func(_ context.Context,f c1handoff.Frame)([]int64,error){
            if f.Kind!=start.Kind||f.SourceID!=start.SourceID||
                f.GenerationID!=start.GenerationID||
                f.ReceiptSHA256!=start.ReceiptSHA256||
                f.ExpectedRecords!=start.ExpectedRecords||
                f.StartBatchIndex!=0||len(f.BatchIDs)!=1||
                f.BatchIDs[0]!=start.BatchIDs[0]{
                return nil,errors.New("C1 mTLS signed generation differs from recorded receiver custody")
            }
            return []int64{batchID},nil
        },
        Dispatch:h.Enqueue,
        Handler:func(ctx context.Context,f c1handoff.Frame)error{
            if f.Kind!=c1handoff.Drain{
                return errors.New("C1 mTLS unexpected synchronous non-Drain")
            }
            return h.Commit(ctx,f)
        },
        FinalProof:func(ctx context.Context,f c1handoff.Frame)(c1handoff.FinalStatus,error){
            if !h.drained||f.ReceiptSHA256!=original.ReceiptSHA256{
                return c1handoff.FinalNone,errors.New("C1 mTLS B proof before durable SQL drain")
            }
            // A different PostgreSQL session reconstructs the signed plan
            // from committed SQL. The actual complete receiver custody is
            // reverified; no fake B boolean or transport ACK is trusted.
            auditor,err:=pgx.ConnectConfig(ctx,worker.Config().Copy())
            if err!=nil{return c1handoff.FinalNone,err}
            defer auditor.Close(context.Background())
            if _,err=auditor.Exec(ctx,"SET default_transaction_read_only = on");err!=nil{
                return c1handoff.FinalNone,err
            }
            p,err:=LoadC1NativePromotionPlan(ctx,auditor,source,
                signed.GenerationID,custody,c1GovernedPendingSchema)
            if err!=nil{return c1handoff.FinalNone,err}
            if err=c1NativeBVerifySignedCustodyWithTrust(ctx,auditor,p,custody,trust);err!=nil{
                return c1handoff.FinalNone,err
            }
            return c1handoff.FinalVerified,nil
        },
    }
    go func(){finished<-srv.ServeConn(ctx,tls.Server(serverHalf,serverTLS))}()
    client,e:=c1handoff.NewClient(tls.Client(clientHalf,clientTLS))
    if e!=nil{t.Fatal(e)}
    defer client.Close()
    if e=client.Send(ctx,start);e!=nil{t.Fatalf("C1 mTLS original signed Start: %v",e)}
    ids:=client.BatchSQLIDs()
    if len(ids)!=1||ids[0]!=batchID{
        t.Fatalf("C1 fi-sor SQL identity changed over authenticated mTLS: %v",ids)
    }
    pipeline,e:=c1handoff.NewClientPipeline(ctx,client,4)
    if e!=nil{t.Fatal(e)}
    defer pipeline.Close()
    remote,e:=newC1RemoteSoRSink(pipeline,source,signed.GenerationID,
        original.ReceiptSHA256)
    if e!=nil{t.Fatal(e)}
    remote.next=2
    if e=remote.EnableSharedRAM(store);e!=nil{t.Fatal(e)}
    if e=remote.Source(ctx,[]privateP6Record{signedRow});e!=nil{t.Fatal(e)}
    if e=remote.Family(ctx,family,[]privateP6Record{signedRow});e!=nil{t.Fatal(e)}
    if e=remote.WaitAll(ctx);e!=nil{t.Fatal(e)}
    if e=remote.Drain(ctx);e!=nil{t.Fatalf("C1 actual signed SQL + independent B Drain: %v",e)}
    if remote.finalStatus!=c1handoff.FinalVerified{
        t.Fatalf("C1 mTLS test must not claim canonical Accepted without the real publisher: %d",remote.finalStatus)
    }
    select{
    case err:=<-finished:
        if err!=nil{t.Fatalf("C1 TLS1.3 two-endpoint signed SQL handoff: %v",err)}
    case <-ctx.Done():
        t.Fatal("C1 signed mTLS RAM PostgreSQL session did not end")
    }
    var pendingParents,pendingTyped,canonicalParents,accepted int64
    if e=admin.QueryRow(ctx,`SELECT
        (SELECT count(*) FROM fi_c1_pending.source_record),
        (SELECT count(*) FROM fi_c1_pending.supporting_source_collection_error),
        (SELECT count(*) FROM fi.source_record),
        (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted')`).
        Scan(&pendingParents,&pendingTyped,&canonicalParents,&accepted);e!=nil{t.Fatal(e)}
    if pendingParents!=1||pendingTyped!=1||canonicalParents!=0||accepted!=0{
        t.Fatalf("C1 signed mTLS SQL escaped pending before canonical publication parent=%d typed=%d canonical=%d accepted=%d",
            pendingParents,pendingTyped,canonicalParents,accepted)
    }
    targets,e:=c1PendingRetireTables()
    if e!=nil{t.Fatal(e)}
    if _,e=admin.Exec(ctx,"TRUNCATE TABLE "+strings.Join(targets,", ")+
        " CONTINUE IDENTITY RESTRICT");e!=nil{
        t.Fatalf("C1 disposable signed mTLS fixture cleanup: %v",e)
    }
    t.Log("PASS: real signed custody -> mTLS1.3 -> prepared RAM -> original C1 SQL parent/typed -> separate read-only signed B; canonical FI untouched")
}
