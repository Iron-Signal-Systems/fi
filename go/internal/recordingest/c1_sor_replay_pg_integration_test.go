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
    "errors"
    "os"
    "strings"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
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
    bad:=original
    bad.prepared.RecordDigest[0]^=1
    if _,err=c1AuditCommittedRowStates(ctx,mustC1ReadOnlyTx(t,ctx,conn),
        []privateP6Record{bad});err==nil{
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
func mustC1ReadOnlyTx(t *testing.T,ctx context.Context,conn *pgx.Conn)pgx.Tx{
    t.Helper()
    tx,e:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly})
    if e!=nil{t.Fatal(e)}
    t.Cleanup(func(){_ =tx.Rollback(context.Background())})
    return tx
}
var _=errors.New
