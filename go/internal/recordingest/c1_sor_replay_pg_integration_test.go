//go:build fi_c1_sor_dev && fi_c1_replay_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// This fixture runs ONLY on a disposable PostgreSQL 18 container with its
// own database identity, never against the populated C220 Source of Record.
package recordingest

import (
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "os"
    "strings"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/jackc/pgx/v5"
)

func TestC1RecoveredSourceParentAndTypedRootPostgres18(t *testing.T){
    if os.Getenv("GITHUB_ACTIONS")!="true"||
        os.Getenv("FI_C1_REPLAY_CI_ALLOW_ISOLATED_WRITES")!="1"{
        t.Skip("no disposable PostgreSQL 18 replay fixture")
    }
    dsn:=os.Getenv("FI_C1_REPLAY_PG_DSN")
    if dsn==""{t.Fatal("C1 replay test: isolated database connection required")}
    ctx,cancel:=context.WithTimeout(context.Background(),120*time.Second)
    defer cancel()
    conn,err:=pgx.Connect(ctx,dsn)
    if err!=nil{t.Fatal(err)}
    defer conn.Close(context.Background())
    var user,db,port string
    var version int
    var existing bool
    if err=conn.QueryRow(ctx,`SELECT current_user,current_database(),
        current_setting('port'),current_setting('server_version_num')::integer,
        to_regnamespace('fi_recovery_projection') IS NOT NULL`).
        Scan(&user,&db,&port,&version,&existing);err!=nil{t.Fatal(err)}
    if user!="fi_c1_test"||db!="fi_c1_replay_integration"||
        port!="5432"||version<180000||existing{
        t.Fatalf("STOP: wrong isolated C1 recovery PostgreSQL identity %s/%s/%s/%d has_schema=%t",
            user,db,port,version,existing)
    }
    if _,err=conn.Exec(ctx,`CREATE SCHEMA fi_recovery_projection`);err!=nil{t.Fatal(err)}
    if _,err=conn.Exec(ctx,`
CREATE TABLE fi_recovery_projection.source_record(
 source_record_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 source_batch_id bigint NOT NULL,
 record_ordinal bigint NOT NULL,
 version text NOT NULL,
 record_kind text NOT NULL,
 scope_id text NOT NULL,
 written_at timestamptz NOT NULL,
 record_bytes integer NOT NULL,
 record_sha256 bytea NOT NULL,
 UNIQUE(source_batch_id,record_ordinal)
)`);err!=nil{t.Fatal(err)}
    kinds:=[]string{"collector_identity","directory_principal_snapshot",
        "file_observation","local_principal_snapshot","ntfs_collection_error",
        "smb_share_snapshot","supporting_source_collection_error","usn_continuity_gap",
        "usn_object_observation","usn_read_boundary",
        "windows_security_continuity_gap","windows_security_coverage",
        "windows_security_event"}
    for _,table:=range kinds{
        if _,err=conn.Exec(ctx,`CREATE TABLE fi_recovery_projection.`+table+
            `(source_record_id bigint PRIMARY KEY REFERENCES fi_recovery_projection.source_record(source_record_id))`);err!=nil{
            t.Fatalf("create disposable typed root %s: %v",table,err)
        }
    }
    raw:=[]byte("{\"version\":\"fi-spool-record/0.1\",\"record_kind\":\"CollectorIdentity\",\"scope_id\":\"c1-replay\",\"written_at\":\"2026-11-21T19:00:00Z\",\"payload\":{\"name\":\"recovery\"}}\n")
    prepared,err:=PrepareSourceRecord(raw)
    if err!=nil{t.Fatal(err)}
    original:=privateP6Record{signedBatchIndex:0,sourceBatchID:44,
        ordinal:1,prepared:prepared}
    stateOf:=func()([]C1RecoveryRowState,error){
        tx,e:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly})
        if e!=nil{return nil,e}
        defer tx.Rollback(context.Background())
        states,e:=c1AuditCommittedRowStates(ctx,tx,[]privateP6Record{original})
        if e!=nil{return nil,e}
        return states,tx.Commit(ctx)
    }
    states,err:=stateOf()
    if err!=nil||len(states)!=1||states[0].ParentCommitted||states[0].TypedRootCommitted{
        t.Fatalf("absent original row falsely committed: %v %+v",err,states)
    }
    var sourceID int64
    err=conn.QueryRow(ctx,`INSERT INTO fi_recovery_projection.source_record
      (source_batch_id,record_ordinal,version,record_kind,scope_id,
       written_at,record_bytes,record_sha256)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING source_record_id`,
        original.sourceBatchID,original.ordinal,prepared.Record.Version,
        prepared.Record.RecordKind,prepared.Record.ScopeID,prepared.WrittenAtUTC,
        prepared.RecordBytes,prepared.RecordDigest[:]).Scan(&sourceID)
    if err!=nil{t.Fatal(err)}
    states,err=stateOf()
    if err!=nil||!states[0].ParentCommitted||states[0].TypedRootCommitted||
        states[0].SourceRecordID!=sourceID{
        t.Fatalf("interrupted after SourceParent COMMIT must request typed replay: %v %+v",err,states)
    }
    batchSHA:=sha256.Sum256(raw)
    signedBatch:=PreparedBatch{BatchID:"batch-original-signed",
        Manifest:spool.Manifest{RecordCount:1,DataBytes:int64(len(raw)),
            DataSHA256:hex.EncodeToString(batchSHA[:])}}
    if err:=c1NativeBVerifyData(ctx,conn,bytes.NewReader(raw),0,44,signedBatch);err==nil{
        t.Fatal("independent signed custody verifier passed before typed root committed")
    }
    selected,err:=c1PartitionRecoveredHandoff(c1handoff.Other,
        []privateP6Record{original},states)
    if err!=nil||len(selected.AlreadyCommitted)!=0||len(selected.MustWrite)!=1{
        t.Fatalf("missing typed root not selected for replay: %v %+v",err,selected)
    }
    if _,err=conn.Exec(ctx,`INSERT INTO fi_recovery_projection.collector_identity(source_record_id)
       VALUES($1)`,sourceID);err!=nil{t.Fatal(err)}
    states,err=stateOf()
    if err!=nil||!states[0].ParentCommitted||!states[0].TypedRootCommitted{
        t.Fatalf("typed COMMIT not identified after crash: %v %+v",err,states)
    }
    if err:=c1NativeBVerifyData(ctx,conn,bytes.NewReader(raw),0,44,signedBatch);err!=nil{
        t.Fatalf("independent B signed source and typed SQL proof failed: %v",err)
    }
    alteredBatch:=signedBatch
    alteredBatch.Manifest.DataSHA256=strings.Repeat("0",64)
    if err:=c1NativeBVerifyData(ctx,conn,bytes.NewReader(raw),0,44,alteredBatch);err==nil{
        t.Fatal("independent B accepted modified signed original batch hash")
    }
    selected,err=c1PartitionRecoveredHandoff(c1handoff.Other,
        []privateP6Record{original},states)
    if err!=nil||len(selected.AlreadyCommitted)!=1||len(selected.MustWrite)!=0{
        t.Fatalf("durable typed root unnecessarily reprojected: %v %+v",err,selected)
    }
    selected,err=c1PartitionRecoveredHandoff(c1handoff.Source,
        []privateP6Record{original},states)
    if err!=nil||len(selected.AlreadyCommitted)!=1||len(selected.MustWrite)!=0{
        t.Fatalf("durable SourceParent unnecessarily duplicated: %v %+v",err,selected)
    }
    // The same read-only replay and B identity proof must work against
    // the governed pending namespace, not just the isolated benchmark
    // namespace. This minimal PostgreSQL18 fixture is intentionally
    // disposable and does not install any canonical SQL objects.
    if _,err=conn.Exec(ctx,"CREATE SCHEMA fi_c1_pending");err!=nil{t.Fatal(err)}
    if _,err=conn.Exec(ctx,`CREATE TABLE fi_c1_pending.source_record (
       LIKE fi_recovery_projection.source_record INCLUDING ALL)`);err!=nil{t.Fatal(err)}
    for _,table:=range kinds{
        if _,err=conn.Exec(ctx,`CREATE TABLE fi_c1_pending.`+table+
            `(source_record_id bigint PRIMARY KEY REFERENCES
               fi_c1_pending.source_record(source_record_id))`);err!=nil{
            t.Fatalf("C1 pending replay typed root %s: %v",table,err)
        }
    }
    var pendingID int64
    err=conn.QueryRow(ctx,`INSERT INTO fi_c1_pending.source_record(
       source_batch_id,record_ordinal,version,record_kind,scope_id,
       written_at,record_bytes,record_sha256)
       VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING source_record_id`,
       original.sourceBatchID,original.ordinal,prepared.Record.Version,
       prepared.Record.RecordKind,prepared.Record.ScopeID,
       prepared.WrittenAtUTC,prepared.RecordBytes,prepared.RecordDigest[:]).
       Scan(&pendingID)
    if err!=nil{t.Fatal(err)}
    checkPending:=func()([]C1RecoveryRowState,error){
        tx,e:=conn.BeginTx(ctx,pgx.TxOptions{
            IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly,
        })
        if e!=nil{return nil,e}
        defer tx.Rollback(context.Background())
        states,e:=c1AuditCommittedRowStates(ctx,tx,
            []privateP6Record{original},c1GovernedPendingSchema)
        if e!=nil{return nil,e}
        return states,tx.Commit(ctx)
    }
    pendingStates,err:=checkPending()
    if err!=nil||len(pendingStates)!=1||
        !pendingStates[0].ParentCommitted||pendingStates[0].TypedRootCommitted{
        t.Fatalf("C1 pending replay missed committed parent before typed root: %+v %v",pendingStates,err)
    }
    if _,err=conn.Exec(ctx,`INSERT INTO fi_c1_pending.collector_identity(source_record_id)
       VALUES($1)`,pendingID);err!=nil{t.Fatal(err)}
    pendingStates,err=checkPending()
    if err!=nil||!pendingStates[0].ParentCommitted||!pendingStates[0].TypedRootCommitted{
        t.Fatalf("C1 pending replay missed committed typed proof: %+v %v",pendingStates,err)
    }
    if err=c1NativeBVerifyData(ctx,conn,bytes.NewReader(raw),0,44,
       signedBatch,c1GovernedPendingSchema);err!=nil{
        t.Fatalf("C1 B original signed custody could not prove pending SQL: %v",err)
    }
    if _,err=conn.Exec(ctx,`UPDATE fi_c1_pending.source_record
        SET record_sha256=$1 WHERE source_record_id=$2`,
        bytes.Repeat([]byte{2},32),pendingID);err!=nil{t.Fatal(err)}
    if _,err=checkPending();err==nil{
        t.Fatal("C1 pending replay accepted mutated committed SourceParent digest")
    }
    // Only one fi-sor may own this generation across processes. The
    // lock vanishes on PostgreSQL session loss, allowing audited recovery.
    owner,lockErr:=pgx.Connect(ctx,dsn)
    if lockErr!=nil{t.Fatal(lockErr)}
    challenger,lockErr:=pgx.Connect(ctx,dsn)
    if lockErr!=nil{_ =owner.Close(context.Background());t.Fatal(lockErr)}
    defer challenger.Close(context.Background())
    var lockA,lockB bool
    if lockErr=owner.QueryRow(ctx,`SELECT pg_try_advisory_lock($1::bigint)`,
        c1PendingSessionLockKey).Scan(&lockA);lockErr!=nil||!lockA{
        t.Fatalf("C1 pending singleton owner failed: %t %v",lockA,lockErr)
    }
    if lockErr=challenger.QueryRow(ctx,`SELECT pg_try_advisory_lock($1::bigint)`,
        c1PendingSessionLockKey).Scan(&lockB);lockErr!=nil||lockB{
        t.Fatalf("C1 pending admitted concurrent SQL owner: %t %v",lockB,lockErr)
    }
    session:=&C1SoRService{pendingSession:owner}
    if lockErr=session.pendingLockHealthy(ctx);lockErr!=nil{
        t.Fatalf("C1 pending owner lost exact advisory lock: %v",lockErr)
    }
    _=owner.Close(context.Background())
    if lockErr=session.pendingLockHealthy(ctx);lockErr==nil{
        t.Fatal("C1 pending failed open after owner SQL connection loss")
    }
    // Connection.Close() can complete before the server backend exits.
    // A competing fi-sor MUST remain blocked until PostgreSQL releases
    // the old *session* lock. Poll briefly instead of assuming an immediate
    // release or forcibly clearing the previous owner's lock.
    deadline:=time.Now().Add(3*time.Second)
    for !lockB && time.Now().Before(deadline) {
        lockErr=challenger.QueryRow(ctx,`SELECT pg_try_advisory_lock($1::bigint)`,
            c1PendingSessionLockKey).Scan(&lockB)
        if lockErr!=nil {
            t.Fatalf("C1 pending competing session lock check: %v",lockErr)
        }
        if !lockB {time.Sleep(20*time.Millisecond)}
    }
    if !lockB{
        t.Fatal("C1 pending restart did not regain advisory ownership after terminated PostgreSQL session")
    }
    bad:=original
    bad.prepared.RecordDigest[0]^=1
    auditTx,e:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly})
    if e!=nil{t.Fatal(e)}
    _,badErr:=c1AuditCommittedRowStates(ctx,auditTx,[]privateP6Record{bad})
    _=auditTx.Rollback(context.Background())
    if badErr==nil{
        t.Fatal("mutated original signed digest accepted as matching committed row")
    }
    // Check the stored SHA-256 independently, too; a mutated SQL digest
    // must not let a replay attach typed children to an unrelated source.
    if _,err=conn.Exec(ctx,`UPDATE fi_recovery_projection.source_record
      SET record_sha256=$1 WHERE source_record_id=$2`,bytes.Repeat([]byte{1},32),sourceID);err!=nil{t.Fatal(err)}
    if _,err=stateOf();err==nil||!strings.Contains(err.Error(),"CONFLICTS"){
        t.Fatalf("mutated PostgreSQL signed SHA should block replay: %v",err)
    }
}
