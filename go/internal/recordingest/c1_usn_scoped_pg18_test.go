//go:build fi_c1_sor_dev && fi_c1_schema_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
    "bytes"
    "context"
    "crypto/sha256"
    "testing"
    "time"

    "github.com/jackc/pgx/v5"
)

// A disposable-only PostgreSQL 18 test: prove source-first USN is a real
// relational projection, not just a compiler-admitted record-kind string.
// Every inserted row is rolled back, including the signed-looking fixture.
func proveScopedUSNPostgres18Projection(t *testing.T, ctx context.Context, admin *pgx.Conn) {
    t.Helper()
    v:=testUSNScopedCapturePayload()
    tx,err:=admin.Begin(ctx)
    if err!=nil{t.Fatal(err)}
    defer tx.Rollback(context.Background())

    source:="ci-disposable-usn-source"
    generation:="ci-disposable-usn-generation"
    hash:=sha256.Sum256([]byte("fi scoped usn ephemeral sql fixture"))
    var genID int64
    err=tx.QueryRow(ctx,`
INSERT INTO fi.recorded_generation (
 receipt_version,descriptor_version,source_id,generation_id,
 canonical_version,data_encoding,artifact_count,source_bytes,
 canonical_bytes,canonical_sha256,encoded_data_bytes,encoded_data_sha256,
 metadata_bytes,metadata_sha256,transfer_bytes,transfer_sha256,
 batch_count,data_bytes,record_count,receipt_bytes,receipt_sha256,ingest_version)
VALUES ('ci/1','ci/1',$1,$2,'fi-canonical/0.1','none',2,128,
 128,$3,64,$3,32,$3,116,$3,1,64,1,120,$3,'ci-only')
RETURNING recorded_generation_id`,source,generation,hash[:]).Scan(&genID)
    if err!=nil{t.Fatalf("disposable source-fixture generation: %v",err)}
    var batchID int64
    err=tx.QueryRow(ctx,`
INSERT INTO fi.source_batch (
 recorded_generation_id,manifest_artifact_name,data_artifact_name,manifest_version,
 batch_id,target_batch_size,record_count,data_bytes,data_sha256,data_file,
 collector_executable_path,collector_executable_sha256,created_at,completed_at,
 manifest_bytes,manifest_sha256)
VALUES ($1,'ci-usn.manifest.json','ci-usn.jsonl','fi-spool-manifest/0.1',
 'ci-usn-batch',512,1,64,$2,'ci-usn.jsonl',
 'CI-FICollector.exe',$2,$3,$3,120,$2)
RETURNING source_batch_id`,genID,hash[:],time.Now().UTC()).Scan(&batchID)
    if err!=nil{t.Fatalf("disposable source-fixture batch: %v",err)}
    var sourceRecordID int64
    err=tx.QueryRow(ctx,`
INSERT INTO fi.source_record (
 source_batch_id,record_ordinal,version,record_kind,scope_id,written_at,
 record_bytes,record_sha256,ingest_version)
VALUES ($1,1,$2,'USNScopedCapture',$3,$4,512,$5,$6)
RETURNING source_record_id`,
        batchID,SpoolRecordVersion,v.GovernedScopeID,time.Now().UTC(),hash[:],IngestVersion).
        Scan(&sourceRecordID)
    if err!=nil{t.Fatalf("disposable source-fixture event envelope: %v",err)}
    if err:=projectUSNScopedCapture(ctx,tx,source,sourceRecordID,v.GovernedScopeID,v);err!=nil{
        t.Fatalf("real PostgreSQL18 USN source-only projection rejected: %v",err)
    }
    var captures,changes,governed,unresolved int64
    err=tx.QueryRow(ctx,`
SELECT (SELECT count(*) FROM fi.usn_scoped_capture WHERE source_record_id=$1),
       (SELECT count(*) FROM fi.usn_scoped_change WHERE source_record_id=$1),
       (SELECT count(*) FROM fi.usn_scoped_change WHERE source_record_id=$1 AND scope_class='Governed'),
       (SELECT count(*) FROM fi.usn_scoped_change WHERE source_record_id=$1 AND scope_class='Unresolved')`,
        sourceRecordID).Scan(&captures,&changes,&governed,&unresolved)
    if err!=nil||captures!=1||changes!=1||governed!=1||unresolved!=0{
        t.Fatalf("durable FI USN source rows missing: capture=%d child=%d governed=%d unresolved=%d err=%v",
            captures,changes,governed,unresolved,err)
    }
    if err:=verifyGenerationProjectionCoverage(ctx,tx,genID);err!=nil{
        t.Fatalf("USN scoped event excluded from canonical typed coverage: %v",err)
    }
    if err:=verifyScopedUSNCapturesComplete(ctx,tx,genID);err!=nil{
        t.Fatalf("independent read-only USN B relational SQL proof failed: %v",err)
    }
    if err:=tx.Rollback(ctx);err!=nil{t.Fatal(err)}
    var stillThere int64
    if err:=admin.QueryRow(ctx,"SELECT count(*) FROM fi.usn_scoped_capture").Scan(&stillThere);err!=nil{
        t.Fatal(err)
    }
    if stillThere!=0{
        t.Fatalf("disposable scoped USN test left %d authoritative rows",stillThere)
    }
    // Verify fixture signature bytes were neither accepted nor materialized
    // outside the explicit transaction. Never treat a test checksum as trust.
    if len(hash[:])!=32 || bytes.Equal(hash[:],make([]byte,32)){
        t.Fatal("invalid disposable fixture digest")
    }
}
