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
    "bytes"
    "crypto/tls"
    "encoding/json"
    "errors"
    "fmt"
    "net"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/jackc/pgx/v5"
)

func c1TestSignedMTLSRAMPostgres18(t *testing.T,ctx context.Context,
    admin,worker,publisher *pgx.Conn,recordCount int){
    t.Helper()
    if os.Getenv("GITHUB_ACTIONS")!="true"||
        os.Getenv("FI_C1_SCHEMA_CI_ALLOW_DISPOSABLE")!="1"{
        t.Fatal("STOP: signed SQL handoff allowed only in disposable FreeBSD CI")
    }
    if admin==nil||worker==nil||publisher==nil||
        admin==worker||admin==publisher||worker==publisher{
        t.Fatal("C1 signed RAM SQL requires distinct administrative and worker identities")
    }
    if recordCount!=1&&recordCount!=3&&recordCount!=5 {
        t.Fatal("C1 signed mTLS fixture supports only 1, 3 or 5 original records")
    }
    root:=t.TempDir()
    source:=fmt.Sprintf("c1-signed-mtls-%d-fixture.iss.local",recordCount)
    for _,dir:=range []string{"custody","recorded","ready",
        filepath.Join("recorded","sources",source)} {
        if e:=os.MkdirAll(filepath.Join(root,dir),0700);e!=nil{t.Fatal(e)}
    }
    var signed m1SignedSource
    if recordCount==1 {
        signed=m1WriteSignedGeneration(t,root,source)
    }else if recordCount==5 {
        signed=c1WriteReceivedThreeBatchGeneration(t,root,source)
    }else{
        // These are real receiver-signed JSONL records, not duplicate
        // SQL-only rows. Different payloads guarantee distinct hashes.
        records:=make([]spool.Record,0,recordCount)
        for i:=0;i<recordCount;i++ {
            records=append(records,spool.Record{
                Version:spool.RecordVersion,
                RecordKind:"SupportingSourceCollectionError",
                ScopeID:"m1-"+source,
                WrittenAt:time.Now().UTC().Format(time.RFC3339Nano),
                Payload:json.RawMessage(fmt.Sprintf(
                    `{"source":"C1-Multi-Handoff","error":"distinct-test-row-%d"}`,i)),
            })
        }
        signed=m1WriteSignedGenerationRecords(t,root,source,records)
    }
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
    wantBatches:=1
    if recordCount==5{wantBatches=3}
    if len(original.Batches)!=wantBatches||
        original.Receipt.RecordCount!=uint64(recordCount){
        t.Fatal("C1 mTLS fixture original signed multi-batch cardinality changed")
    }
    batchNames:=make([]string,len(original.Batches))
    batchCounts:=make([]int64,len(original.Batches))
    for i,batch:=range original.Batches {
        batchNames[i]=batch.BatchID
        batchCounts[i]=int64(batch.Manifest.RecordCount)
    }
    start:=c1handoff.Frame{
        Kind:c1handoff.Start,Sequence:1,SourceID:source,
        GenerationID:signed.GenerationID,ReceiptSHA256:original.ReceiptSHA256,
        ExpectedRecords:int64(original.Receipt.RecordCount),
        BatchIDs:batchNames,
    }
    if e=start.Validate();e!=nil{t.Fatal(e)}
    // Admission is the exact production fi-sor PostgreSQL transaction,
    // but the trust resolver is injected only in this signed fixture.
    if e=c1StageVerifiedPendingMetadata(ctx,worker,start,original);e!=nil{
        t.Fatalf("C1 authentic signed mTLS Pending bootstrap: %v",e)
    }
    batchSQLIDs:=make([]int64,len(batchNames))
    signedRows:=make([]privateP6Record,0,recordCount)
    for i,batch:=range original.Batches {
        if e=admin.QueryRow(ctx,`SELECT source_batch_id FROM fi_c1_pending.source_batch
            WHERE batch_id=$1`,batch.BatchID).Scan(&batchSQLIDs[i]);e!=nil{t.Fatal(e)}
        raw,readErr:=os.ReadFile(filepath.Join(root,source,"frozen",
            batch.DataArtifactName))
        if readErr!=nil{t.Fatal(readErr)}
        lines:=bytes.SplitAfter(raw,[]byte{'\n'})
        ordinal:=int64(0)
        for _,line:=range lines {
            if len(line)==0{continue}
            prepared,prepErr:=PrepareSourceRecord(line)
            if prepErr!=nil{t.Fatal(prepErr)}
            if prepared.Record.RecordKind!="SupportingSourceCollectionError" {
                t.Fatal("C1 signed multi-batch record changed its typed projector")
            }
            ordinal++
            signedRows=append(signedRows,privateP6Record{
                signedBatchIndex:i,sourceBatchID:batchSQLIDs[i],
                ordinal:ordinal,prepared:prepared,
            })
        }
        if ordinal!=batchCounts[i]{
            t.Fatalf("C1 source batch %d signed ordinals=%d manifest=%d",i,ordinal,batchCounts[i])
        }
    }
    if len(signedRows)!=recordCount{
        t.Fatalf("C1 signed source across real batches rows=%d expected=%d",len(signedRows),recordCount)
    }
    family,e:=privateP6KindFamily(signedRows[0].prepared.Record.RecordKind)
    if e!=nil{t.Fatal(e)}
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
        original.ReceiptSHA256,batchSQLIDs,
        batchCounts,int64(original.Receipt.RecordCount))
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
                f.StartBatchIndex!=0||len(f.BatchIDs)!=len(batchNames){
                return nil,errors.New("C1 mTLS signed generation differs from recorded receiver custody")
            }
            for i,name:=range f.BatchIDs {
                if name!=batchNames[i]{
                    return nil,errors.New("C1 mTLS foreign signed source batch roster")
                }
            }
            return append([]int64(nil),batchSQLIDs...),nil
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
    if len(ids)!=len(batchSQLIDs){
        t.Fatalf("C1 fi-sor SQL roster length changed over authenticated mTLS: %v",ids)
    }
    for i,id:=range ids{
        if id!=batchSQLIDs[i]{
            t.Fatalf("C1 fi-sor SQL batch identity %d changed over authenticated mTLS: %v",i,ids)
        }
    }
    pipeline,e:=c1handoff.NewClientPipeline(ctx,client,4)
    if e!=nil{t.Fatal(e)}
    defer pipeline.Close()
    remote,e:=newC1RemoteSoRSink(pipeline,source,signed.GenerationID,
        original.ReceiptSHA256)
    if e!=nil{t.Fatal(e)}
    remote.next=2
    if e=remote.EnableSharedRAM(store);e!=nil{t.Fatal(e)}
    if recordCount==1{
        if e=remote.Source(ctx,signedRows);e!=nil{t.Fatal(e)}
        if e=remote.Family(ctx,family,signedRows);e!=nil{t.Fatal(e)}
    }else if recordCount==3{
        if e=remote.Source(ctx,signedRows[:2]);e!=nil{t.Fatal(e)}
        if e=remote.Source(ctx,signedRows[2:]);e!=nil{t.Fatal(e)}
        if e=remote.Family(ctx,family,signedRows[:1]);e!=nil{t.Fatal(e)}
        if e=remote.Family(ctx,family,signedRows[1:]);e!=nil{t.Fatal(e)}
    }else{
        // Source spans batch 0 and 1 in its first handoff; the second
        // handoff completes batch 1 and begins batch 2. Typed SQL cuts
        // occur at different positions and must retain signed identity.
        if e=remote.Source(ctx,signedRows[:3]);e!=nil{t.Fatal(e)}
        if e=remote.Source(ctx,signedRows[3:]);e!=nil{t.Fatal(e)}
        if e=remote.Family(ctx,family,signedRows[:2]);e!=nil{t.Fatal(e)}
        if e=remote.Family(ctx,family,signedRows[2:]);e!=nil{t.Fatal(e)}
    }
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
        (SELECT count(*) FROM fi.source_record WHERE source_batch_id IN (
           SELECT b.source_batch_id FROM fi.source_batch b
           JOIN fi.recorded_generation g USING(recorded_generation_id)
           WHERE g.source_id=$1 AND g.generation_id=$2)),
        (SELECT count(*) FROM fi.ingest_journal
           WHERE source_id=$1 AND generation_id=$2 AND outcome='Accepted')`,
        source,signed.GenerationID).
        Scan(&pendingParents,&pendingTyped,&canonicalParents,&accepted);e!=nil{t.Fatal(e)}
    if pendingParents!=int64(recordCount)||pendingTyped!=int64(recordCount)||
        canonicalParents!=0||accepted!=0{
        t.Fatalf("C1 signed mTLS SQL escaped pending before canonical publication parent=%d typed=%d canonical=%d accepted=%d",
            pendingParents,pendingTyped,canonicalParents,accepted)
    }

    // The handoff has returned only FinalVerified. Separately exercise the
    // SAME atomic populated-SoR remapper using the actual receiver-signed
    // generation, not a synthetic callback that assumes evidence exists.
    // Native B proof is repeated under publisher table locks and is bound
    // to the independently reopened original custody and all typed roots.
    verifier,e:=pgx.ConnectConfig(ctx,worker.Config().Copy())
    if e!=nil{t.Fatal(e)}
    defer verifier.Close(context.Background())
    if _,e=verifier.Exec(ctx,"SET default_transaction_read_only = on");e!=nil{
        t.Fatal(e)
    }
    promotionPlan,e:=LoadC1NativePromotionPlan(ctx,verifier,source,
        signed.GenerationID,custody,c1GovernedPendingSchema)
    if e!=nil{t.Fatalf("C1 real signed canonical promotion plan: %v",e)}
    // The separately executing B process must reject a SQL digest which
    // differs from immutable signed custody before publication is allowed.
    // Mutation and restoration are limited to this disposable CI database.
    if _,e=admin.Exec(ctx,`UPDATE fi_c1_pending.source_record
        SET record_sha256=$1 WHERE source_batch_id=$2 AND record_ordinal=1`,
        bytes.Repeat([]byte{0x5e},32),batchSQLIDs[0]);e!=nil{t.Fatal(e)}
    corrupted:=c1TestRunIndependentSignedBProcess(ctx,t,worker,
        promotionPlan,custody,signed.Trust)
    if corrupted==nil||!strings.Contains(corrupted.Error(),"CONFLICTS"){
        t.Fatalf("C1 separate B OS process failed to reject tampered committed digest: %v",corrupted)
    }
    if _,e=admin.Exec(ctx,`UPDATE fi_c1_pending.source_record
        SET record_sha256=$1 WHERE source_batch_id=$2 AND record_ordinal=1`,
        signedRows[0].prepared.RecordDigest[:],batchSQLIDs[0]);e!=nil{t.Fatal(e)}
    // This is a REAL distinct FreeBSD OS process, not the same Go goroutine
    // as the C1 writer. Its own SQL session is fi_ingest, read-only, and
    // its input is only the original verified receiver trust/custody and
    // committed Pending SQL metadata. No synthetic completion boolean.
    if e=c1TestRunIndependentSignedBProcess(ctx,t,worker,
        promotionPlan,custody,signed.Trust);e!=nil{
        t.Fatalf("C1 independent B OS process before canonical publication: %v",e)
    }
    generation,e:=c1NativePromotionGeneration(promotionPlan)
    if e!=nil{t.Fatal(e)}
    attempt:="c1-genuine-signed-"+signed.GenerationID
    fullProof:=func(ctx context.Context,conn *pgx.Conn,g *PreparedGeneration,
        _ BacklogWindowLimits)(BacklogGenerationVerification,error){
        return c1NativeFullPromotionProofWithTrust(ctx,conn,g,
            promotionPlan,custody,trust)
    }
    result,e:=promoteVerifiedBacklogToPopulatedSoRWithProofSchema(ctx,
        verifier,publisher,generation,BacklogWindowLimits{},attempt,fullProof,
        c1GovernedPendingSchema)
    if e!=nil{t.Fatalf("C1 actual receiver-signed canonical transaction: %v",e)}
    if result.Outcome!="Accepted"||result.RecordsCommitted!=int64(recordCount){
        t.Fatalf("C1 actual signed generation failed canonical Accepted transaction: %+v",result)
    }
    check,e:=verifier.BeginTx(ctx,pgx.TxOptions{
        IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly,
    })
    if e!=nil{t.Fatal(e)}
    canonical,e:=c1CanonicalStatusInSnapshot(ctx,check,source,
        signed.GenerationID,original.ReceiptSHA256)
    if e!=nil||canonical!=c1handoff.FinalAccepted{
        _=check.Rollback(context.Background())
        t.Fatalf("C1 actual signed canonical Accepted readback failed: %v %v",canonical,e)
    }
    if e=check.Commit(ctx);e!=nil{t.Fatal(e)}
    var committedSource,committedTyped int64
    if e=admin.QueryRow(ctx,`SELECT
       (SELECT count(*) FROM fi.source_record r
         JOIN fi.source_batch b USING(source_batch_id)
         JOIN fi.recorded_generation g USING(recorded_generation_id)
         WHERE g.source_id=$1 AND g.generation_id=$2),
       (SELECT count(*) FROM fi.supporting_source_collection_error x
         JOIN fi.source_record r USING(source_record_id)
         JOIN fi.source_batch b USING(source_batch_id)
         JOIN fi.recorded_generation g USING(recorded_generation_id)
         WHERE g.source_id=$1 AND g.generation_id=$2)`,
        source,signed.GenerationID).
        Scan(&committedSource,&committedTyped);e!=nil{t.Fatal(e)}
    if committedSource!=int64(recordCount)||committedTyped!=int64(recordCount){
        t.Fatalf("C1 real signed canonical typed projection lost parent/child: %d/%d",
            committedSource,committedTyped)
    }
    // Verify every original signed ordinal and full SHA-256 in canonical
    // FI. A source/typed row count alone could miss reordered or duplicated
    // identities when consecutive RAM handoffs cross SQL transaction cuts.
    canonicalRows,e:=admin.Query(ctx,`SELECT b.batch_id,r.record_ordinal,r.record_sha256
        FROM fi.source_record r
        JOIN fi.source_batch b USING(source_batch_id)
        JOIN fi.recorded_generation g USING(recorded_generation_id)
        WHERE g.source_id=$1 AND g.generation_id=$2
        ORDER BY b.batch_id,r.record_ordinal`,source,signed.GenerationID)
    if e!=nil{t.Fatal(e)}
    ordinalCount:=0
    for canonicalRows.Next(){
        var ordinal int64
        var batchName string
        var digest []byte
        if e=canonicalRows.Scan(&batchName,&ordinal,&digest);e!=nil{break}
        if ordinalCount>=len(signedRows) {
            e=errors.New("C1 canonical unexpected extra signed ordinal")
            break
        }
        expected:=signedRows[ordinalCount]
        if batchName!=batchNames[expected.signedBatchIndex]||
            ordinal!=expected.ordinal||
            !bytes.Equal(digest,expected.prepared.RecordDigest[:]){
            e=errors.New("C1 canonical SourceParent ordinal or original signed SHA-256 changed across RAM/SQL transactions")
            break
        }
        ordinalCount++
    }
    if e==nil{e=canonicalRows.Err()}
    canonicalRows.Close()
    if e!=nil||ordinalCount!=recordCount{
        t.Fatalf("C1 canonical exact signed ordinal/digest mapping: rows=%d expected=%d err=%v",ordinalCount,recordCount,e)
    }
    again,e:=promoteVerifiedBacklogToPopulatedSoRWithProofSchema(ctx,
        verifier,publisher,generation,BacklogWindowLimits{},attempt+"-retry",
        fullProof,c1GovernedPendingSchema)
    if e!=nil||again.Outcome!="AlreadyAccepted"{
        t.Fatalf("C1 genuine signed duplicate canonical retry: %+v %v",again,e)
    }
    // Only AFTER independent canonical Accepted may this test invoke the
    // production retirement transaction. Real custody remains immutable.
    retire,e:=publisher.Begin(ctx)
    if e!=nil{t.Fatal(e)}
    if e=c1RetireAcceptedPendingTx(ctx,retire,source,
        signed.GenerationID,original.ReceiptSHA256);e!=nil{
        _=retire.Rollback(context.Background())
        t.Fatalf("C1 signed canonical Accepted pending retirement: %v",e)
    }
    if e=retire.Commit(ctx);e!=nil{t.Fatal(e)}
    var remaining int64
    if e=admin.QueryRow(ctx,`SELECT count(*) FROM fi_c1_pending.recorded_generation`).
        Scan(&remaining);e!=nil{t.Fatal(e)}
    if remaining!=0{t.Fatal("C1 signed canonical retirement did not clear Pending")}
    t.Logf("PASS: %d original signed records across %d SQL source handoffs, independent typed transactions, separate FreeBSD B child and one atomic canonical Accepted + Pending retirement",recordCount,func()int{if recordCount==1{return 1};return 2}())
}
