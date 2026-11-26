//go:build freebsd && fi_c1_sor_dev && fi_c1_schema_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// DISPOSABLE FreeBSD/PG18 only. A shell stops PostgreSQL with -m immediate
// between two distinct go test processes. No C220, persistent on-prem SQL,
// or production receiver trust is ever opened by this fixture.
package recordingest

import (
    "bytes"
    "context"
    "crypto/x509"
    "encoding/json"
    "encoding/hex"
    "errors"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/jackc/pgx/v5"
)

// c1SignedBProcessFixture stores only TEST proof inputs across the deliberate
// PostgreSQL crash; neither a secret key nor a generated Accepted marker.
func TestC1SignedPostgres18ImmediateCrashRecovery(t *testing.T) {
    phase:=os.Getenv("FI_C1_CI_CRASH_PHASE")
    if phase==""{t.Skip("only the native FreeBSD immediate-stop harness")}
    if phase!="before"&&phase!="after"{t.Fatal("invalid C1 crash test phase")}
    if os.Getenv("GITHUB_ACTIONS")!="true"||
        os.Getenv("FI_C1_SCHEMA_CI_ALLOW_DISPOSABLE")!="1"{
        t.Fatal("STOP: signed PostgreSQL crash test requires disposable CI")
    }
    root:=os.Getenv("FI_C1_CI_CRASH_ROOT")
    if !filepath.IsAbs(root)||filepath.Clean(root)!=root||
       !strings.HasPrefix(root,"/var/tmp/fi-c1-pg18-vm.")||
       !strings.HasSuffix(root,"/signed-crash") {
        t.Fatalf("STOP: unsafe signed crash fixture path %q",root)
    }
    ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second)
    defer cancel()
    admin,err:=pgx.Connect(ctx,os.Getenv("FI_C1_SCHEMA_CI_ADMIN_DSN"))
    if err!=nil{t.Fatal(err)}
    defer admin.Close(context.Background())
    var user,db,port,fsync,syncCommit,fullPages string
    var version int
    err=admin.QueryRow(ctx,`SELECT current_user,current_database(),
         current_setting('port'),current_setting('server_version_num')::int,
         current_setting('fsync'),current_setting('synchronous_commit'),
         current_setting('full_page_writes')`).
        Scan(&user,&db,&port,&version,&fsync,&syncCommit,&fullPages)
    if err!=nil{t.Fatal(err)}
    if user!="fi_c1_schema_test"||db!="fi"||port!="5432"||
        version<180000||version>=190000||fsync!="on"||
        syncCommit!="on"||fullPages!="on"{
        t.Fatalf("STOP: non-disposable or non-durable database %s/%s/%s version=%d fsync=%s commit=%s full_pages=%s",
            user,db,port,version,fsync,syncCommit,fullPages)
    }
    workerConfig:=admin.Config().Copy()
    workerConfig.User="fi_ingest"
    workerConfig.Password="isolated-only-test"
    worker,err:=pgx.ConnectConfig(ctx,workerConfig)
    if err!=nil{t.Fatal(err)}
    defer worker.Close(context.Background())
    if phase=="before" {
        c1SignedCrashBefore(t,ctx,root,admin,worker)
        return
    }
    publisherConfig:=admin.Config().Copy()
    publisherConfig.User=c1PublisherRole
    publisherConfig.Password="isolated-only-test"
    publisher,err:=pgx.ConnectConfig(ctx,publisherConfig)
    if err!=nil{t.Fatal(err)}
    defer publisher.Close(context.Background())
    c1SignedCrashAfter(t,ctx,root,admin,worker,publisher)
}

func c1SignedCrashBefore(t *testing.T,ctx context.Context,root string,
    admin,worker *pgx.Conn){
    t.Helper()
    if err:=os.MkdirAll(root,0700);err!=nil{t.Fatal(err)}
    source:="c1-signed-immediate.iss.local"
    for _,dir:=range []string{"custody","recorded","ready",
        filepath.Join("recorded","sources",source)}{
        if err:=os.MkdirAll(filepath.Join(root,dir),0700);err!=nil{t.Fatal(err)}
    }
    signed:=m1WriteSignedGeneration(t,root,source)
    custody:=c1NativeBCustodyConfig{CustodyRoot:filepath.Join(root,"custody"),
        RecordedRoot:filepath.Join(root,"recorded"),SourceNamespaces:true,
        MaxCanonicalBytes:64<<20,MaxEncodedBytes:64<<20,
        MaxManifestBytes:1<<20}
    trust:=func(id string)(generationTrustBundle,error){
        if id!=source{return generationTrustBundle{},errors.New("foreign signed source")}
        return signed.Trust,nil
    }
    original,err:=c1StreamOriginalSignedManifestPlanWithTrust(
        ctx,source,signed.GenerationID,custody,trust)
    if err!=nil{t.Fatal(err)}
    if len(original.Batches)!=1||original.Receipt.RecordCount!=1{
        t.Fatal("signed crash fixture is not one original record/batch")
    }
    start:=c1handoff.Frame{Kind:c1handoff.Start,Sequence:1,SourceID:source,
        GenerationID:signed.GenerationID,ReceiptSHA256:original.ReceiptSHA256,
        ExpectedRecords:1,BatchIDs:[]string{original.Batches[0].BatchID}}
    if err=c1StageVerifiedPendingMetadata(ctx,worker,start,original);err!=nil{t.Fatal(err)}
    var batchID int64
    if err=admin.QueryRow(ctx,`SELECT source_batch_id FROM fi_c1_pending.source_batch
        WHERE batch_id=$1`,start.BatchIDs[0]).Scan(&batchID);err!=nil{t.Fatal(err)}
    raw,err:=os.ReadFile(filepath.Join(root,source,"frozen",
        original.Batches[0].DataArtifactName))
    if err!=nil{t.Fatal(err)}
    prepared,err:=PrepareSourceRecord(raw)
    if err!=nil{t.Fatal(err)}
    open:=func(ctx context.Context,_,_ string)(*pgx.Conn,int64,error){
        c,e:=pgx.ConnectConfig(ctx,worker.Config().Copy())
        if e!=nil{return nil,0,e}
        var pid int64
        if e=c.QueryRow(ctx,"SELECT pg_backend_pid()::bigint").Scan(&pid);e!=nil{
            _=c.Close(context.Background());return nil,0,e
        }
        return c,pid,nil
    }
    pool,err:=newC1SQLWithOpener(ctx,"","",source,2,false,open,
        false,c1GovernedPendingSchema)
    if err!=nil{t.Fatal(err)}
    row:=privateP6Record{sourceBatchID:batchID,signedBatchIndex:0,
        ordinal:1,prepared:prepared}
    if err=pool.Source(ctx,[]privateP6Record{row});err!=nil{
        pool.Close();t.Fatal(err)
    }
    if err=pool.WaitSource(ctx);err!=nil{pool.Close();t.Fatal(err)}
    pool.Close()
    var parents,typed,accepted int64
    err=admin.QueryRow(ctx,`SELECT
       (SELECT count(*) FROM fi_c1_pending.source_record),
       (SELECT count(*) FROM fi_c1_pending.supporting_source_collection_error),
       (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'
        AND source_id=$1 AND generation_id=$2)`,source,signed.GenerationID).
        Scan(&parents,&typed,&accepted)
    if err!=nil||parents!=1||typed!=0||accepted!=0{
        t.Fatalf("pre-crash SQL not exactly one committed original parent: %d/%d/%d %v",parents,typed,accepted,err)
    }
    plan,err:=LoadC1NativePromotionPlan(ctx,worker,source,
        signed.GenerationID,custody,c1GovernedPendingSchema)
    if err!=nil{t.Fatal(err)}
    f:=c1SignedBProcessFixture{Plan:plan,Custody:custody,
        RootDER:signed.Trust.Root.Raw,IssuerDER:signed.Trust.BatchIssuer.Raw,
        CRLDER:signed.Trust.BatchCRL.Raw,Source:signed.Trust.Source}
    b,err:=json.Marshal(f)
    if err!=nil{t.Fatal(err)}
    if err=os.WriteFile(filepath.Join(root,"fixture.json"),b,0600);err!=nil{t.Fatal(err)}
    t.Log("PASS: receiver-signed original custody + SourceParent COMMITTED, typed and Accepted ABSENT before PostgreSQL immediate stop")
}

func c1SignedCrashAfter(t *testing.T,ctx context.Context,root string,
    admin,worker,publisher *pgx.Conn){
    t.Helper()
    info,err:=os.Lstat(filepath.Join(root,"fixture.json"))
    if err!=nil||!info.Mode().IsRegular()||info.Mode().Perm()!=0600{
        t.Fatalf("signed crash fixture missing or unsafe after database restart: %v",err)
    }
    data,err:=os.ReadFile(filepath.Join(root,"fixture.json"))
    if err!=nil{t.Fatal(err)}
    var f c1SignedBProcessFixture
    if err=json.Unmarshal(data,&f);err!=nil{t.Fatal(err)}
    p,custody:=f.Plan,f.Custody
    if err=c1ValidateNativeBPlan(p);err!=nil{t.Fatal(err)}
    if p.SQLSchema!=c1GovernedPendingSchema||p.Start.ExpectedRecords!=1||
        len(p.SQLIDs)!=1||len(p.Batches)!=1||
        custody.CustodyRoot!=filepath.Join(root,"custody")||
        custody.RecordedRoot!=filepath.Join(root,"recorded"){
        t.Fatal("post-crash original signed SQL/custody identity differs")
    }
    rootCA,err:=x509.ParseCertificate(f.RootDER)
    if err!=nil{t.Fatal(err)}
    issuer,err:=x509.ParseCertificate(f.IssuerDER)
    if err!=nil{t.Fatal(err)}
    crl,err:=x509.ParseRevocationList(f.CRLDER)
    if err!=nil{t.Fatal(err)}
    trust:=func(id string)(generationTrustBundle,error){
        if id!=p.Start.SourceID||f.Source.SourceID!=id{
            return generationTrustBundle{},errors.New("signed crash source trust changed")
        }
        return generationTrustBundle{Root:rootCA,BatchIssuer:issuer,
            BatchCRL:crl,Source:f.Source},nil
    }
    original,err:=c1StreamOriginalSignedManifestPlanWithTrust(ctx,
        p.Start.SourceID,p.Start.GenerationID,custody,trust)
    if err!=nil{t.Fatalf("original signed custody missing after PostgreSQL crash: %v",err)}
    if original.ReceiptSHA256!=p.Start.ReceiptSHA256||
        original.Receipt.TransferSHA256!=p.Transfer||
        len(original.Batches)!=1||
        original.Batches[0].BatchID!=p.Batches[0].BatchID{
        t.Fatal("signed original receiver receipt/transfer changed across PostgreSQL crash")
    }
    raw,err:=os.ReadFile(filepath.Join(root,p.Start.SourceID,"frozen",
        original.Batches[0].DataArtifactName))
    if err!=nil{t.Fatal(err)}
    prepared,err:=PrepareSourceRecord(raw)
    if err!=nil{t.Fatal(err)}
    family,err:=privateP6KindFamily(prepared.Record.RecordKind)
    if err!=nil{t.Fatal(err)}
    row:=privateP6Record{signedBatchIndex:0,sourceBatchID:p.SQLIDs[0],
        ordinal:1,prepared:prepared}
    reader,err:=pgx.ConnectConfig(ctx,worker.Config().Copy())
    if err!=nil{t.Fatal(err)}
    defer reader.Close(context.Background())
    if _,err=reader.Exec(ctx,"SET default_transaction_read_only=on");err!=nil{t.Fatal(err)}
    check:=func()([]C1RecoveryRowState,error){
        tx,e:=reader.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.RepeatableRead,
            AccessMode:pgx.ReadOnly})
        if e!=nil{return nil,e}
        defer tx.Rollback(context.Background())
        results,e:=c1AuditCommittedRowStates(ctx,tx,
            []privateP6Record{row},c1GovernedPendingSchema)
        if e!=nil{return nil,e}
        return results,tx.Commit(ctx)
    }
    state,err:=check()
    if err!=nil||len(state)!=1||!state[0].ParentCommitted||
        state[0].TypedRootCommitted{
        t.Fatalf("PG18 crash recovery did not preserve exact signed parent-only commit: %+v %v",state,err)
    }
    if err=c1NativeBVerifyData(ctx,reader,bytes.NewReader(raw),0,
        p.SQLIDs[0],p.Batches[0],c1GovernedPendingSchema);err==nil{
        t.Fatal("independent B accepted uncommitted typed root following immediate stop")
    }
    open:=func(ctx context.Context,_,_ string)(*pgx.Conn,int64,error){
        c,e:=pgx.ConnectConfig(ctx,worker.Config().Copy())
        if e!=nil{return nil,0,e}
        var pid int64
        if e=c.QueryRow(ctx,"SELECT pg_backend_pid()::bigint").Scan(&pid);e!=nil{
            _=c.Close(context.Background());return nil,0,e
        }
        return c,pid,nil
    }
    pool,err:=newC1SQLWithOpener(ctx,"","",p.Start.SourceID,2,false,
        open,false,c1GovernedPendingSchema)
    if err!=nil{t.Fatal(err)}
    defer pool.Close()
    groups,err:=c1SoRGroupPlan(p.Batches,0)
    if err!=nil{t.Fatal(err)}
    tracker,err:=c1SoRCommitTracker(groups)
    if err!=nil{t.Fatal(err)}
    pool.commitReady=tracker
    handler,err:=newC1SoRCommitHandler(pool,p.Start.SourceID,
        p.Start.GenerationID,p.Start.ReceiptSHA256,p.SQLIDs,[]int64{1},1)
    if err!=nil{t.Fatal(err)}
    signedRow:=c1handoff.Row{SignedBatchIndex:0,SourceBatchID:p.SQLIDs[0],
        Ordinal:1,Digest:prepared.RecordDigest,RawRecord:raw}
    frame:=func(kind c1handoff.Kind,seq uint64)c1handoff.Frame{
        return c1handoff.Frame{Kind:kind,Sequence:seq,
            SourceID:p.Start.SourceID,GenerationID:p.Start.GenerationID,
            ReceiptSHA256:p.Start.ReceiptSHA256,
            Rows:[]c1handoff.Row{signedRow}}
    }
    parentFuture,err:=handler.EnqueueReplay(ctx,frame(c1handoff.Source,2),reader)
    if err!=nil{t.Fatal(err)}
    if ack,ok:=<-parentFuture;!ok||ack!=nil{t.Fatalf("signed parent replay: %v %t",ack,ok)}
    if err=tracker.Seal(1);err!=nil{t.Fatal(err)}
    typedFuture,err:=handler.EnqueueReplay(ctx,
        frame(c1handoff.Kind(family+2),3),reader)
    if err!=nil{t.Fatal(err)}
    if ack,ok:=<-typedFuture;!ok||ack!=nil{
        t.Fatalf("signed typed replay SQL COMMIT: %v %t",ack,ok)
    }
    if err=pool.WaitAll(ctx);err!=nil{t.Fatal(err)}
    if err=tracker.FinishCommitted();err!=nil{t.Fatal(err)}
    state,err=check()
    if err!=nil||len(state)!=1||!state[0].ParentCommitted||
        !state[0].TypedRootCommitted{
        t.Fatalf("signed typed SQL replay incomplete after PostgreSQL crash: %+v %v",state,err)
    }
    if err=c1NativeBVerifySignedCustodyWithTrust(ctx,reader,p,custody,trust);err!=nil{
        t.Fatalf("independent B rejected original signed complete replay after crash: %v",err)
    }
    g,err:=c1NativePromotionGeneration(p)
    if err!=nil{t.Fatal(err)}
    // Exercise the SAME single-custody-pass commitment that the fi-sor
    // child returns during signed group proof. The original C1 group
    // relational verifier is reused, not replaced by a new projector.
    originalCommitment,err:=c1NativeBNewRowCommitment(p)
    if err!=nil{t.Fatal(err)}
    groupStarts,groupCompletes:=0,0
    err=c1NativeBVerifySignedCustodyGroupsWithTrust(ctx,reader,p,custody,trust,
        func(wi int,complete bool)error{
            if wi!=1{return errors.New("native B streamed unexpected original group")}
            if !complete{groupStarts++;return nil}
            groupCompletes++
            return privateC1AsyncVerifyGroup(ctx,reader,g,p.Descriptors,wi,p.SQLSchema)
        },originalCommitment)
    if err!=nil{t.Fatalf("original C1 group B signed streaming failed: %v",err)}
    if groupStarts!=1||groupCompletes!=1{
        t.Fatal("B did not verify the original committed group exactly once")
    }
    signedProof:=hex.EncodeToString(originalCommitment.Sum(nil))
    lockedSQLProof,err:=c1NativeBLockedSQLRowCommitment(ctx,reader,p)
    if err!=nil{t.Fatalf("signed original SQL commitment readback: %v",err)}
    if signedProof!=lockedSQLProof{
        t.Fatal("original signed B proof and PostgreSQL row identity differ")
    }
    // Change ONLY persisted Pending SQL, not immutable signed custody.
    // The publisher's under-lock comparison must reject the drift; restore
    // the original source SHA only for the disposable accepted crash fixture.
    if _,err=admin.Exec(ctx,`UPDATE fi_c1_pending.source_record
        SET record_sha256=$1 WHERE source_batch_id=$2 AND record_ordinal=1`,
        bytes.Repeat([]byte{0xbd},32),p.SQLIDs[0]);err!=nil{t.Fatal(err)}
    changedSQLProof,e:=c1NativeBLockedSQLRowCommitment(ctx,reader,p)
    if e!=nil{t.Fatal(e)}
    if changedSQLProof==signedProof{
        t.Fatal("publisher accepted Pending SQL digest mutation after independent B proof")
    }
    if _,err=admin.Exec(ctx,`UPDATE fi_c1_pending.source_record
        SET record_sha256=$1 WHERE source_batch_id=$2 AND record_ordinal=1`,
        prepared.RecordDigest[:],p.SQLIDs[0]);err!=nil{t.Fatal(err)}
    restoredProof,e:=c1NativeBLockedSQLRowCommitment(ctx,reader,p)
    if e!=nil||restoredProof!=signedProof{
        t.Fatalf("restored signed SQL identity does not match original B: %v",e)
    }
    // Exercise the single-jail publisher path itself: B's original signed
    // rows were proven above. The publisher now compares the independently
    // derived commitment under Pending SHARE locks, then remaps atomically.
    // It must NOT invoke the obsolete full-custody replay callback.
    accepted,err:=PromoteC1VerifiedToPopulatedSoRWithCommitment(ctx,
        reader,publisher,p,
        "c1-ci-signed-actual-immediate-"+p.Start.GenerationID,signedProof)
    if err!=nil{t.Fatalf("signed crash canonical publication: %v",err)}
    if accepted.Outcome!="Accepted"||accepted.RecordsCommitted!=1{
        t.Fatalf("signed crash canonical publication incorrect: %+v",accepted)
    }
    var journal,parents,typed int64
    err=admin.QueryRow(ctx,`SELECT
      (SELECT count(*) FROM fi.ingest_journal WHERE source_id=$1
       AND generation_id=$2 AND outcome='Accepted'),
      (SELECT count(*) FROM fi.source_record r
       JOIN fi.source_batch b USING(source_batch_id)
       JOIN fi.recorded_generation g USING(recorded_generation_id)
       WHERE g.source_id=$1 AND g.generation_id=$2),
      (SELECT count(*) FROM fi.supporting_source_collection_error x
       JOIN fi.source_record r USING(source_record_id)
       JOIN fi.source_batch b USING(source_batch_id)
       JOIN fi.recorded_generation g USING(recorded_generation_id)
       WHERE g.source_id=$1 AND g.generation_id=$2)`,
       p.Start.SourceID,p.Start.GenerationID).Scan(&journal,&parents,&typed)
    if err!=nil||journal!=1||parents!=1||typed!=1{
        t.Fatalf("signed post-crash canonical rows/Accepted incorrect: %d/%d/%d %v",
            parents,typed,journal,err)
    }
    retire,err:=publisher.Begin(ctx)
    if err!=nil{t.Fatal(err)}
    if err=c1RetireAcceptedPendingTx(ctx,retire,p.Start.SourceID,
        p.Start.GenerationID,p.Start.ReceiptSHA256);err!=nil{
        _=retire.Rollback(context.Background());t.Fatal(err)
    }
    if err=retire.Commit(ctx);err!=nil{t.Fatal(err)}
    t.Log("PASS: actual PostgreSQL18 immediate-stop WAL recovery retained exactly one signed parent, replayed only missing typed SQL, B reverified original custody and canonical Accepted exactly once")
}
