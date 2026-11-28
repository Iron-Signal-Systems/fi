//go:build fi_c1_sor_dev && fi_c1_schema_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
    "context"
    "crypto/sha256"
    "testing"
    "time"

    "github.com/jackc/pgx/v5"
)

// On REAL disposable PostgreSQL 18, project an independently scheduled
// Windows-style missing File-ID outcome against the exact original signed
// scoped source, then independently reject forged trigger/source/NTFS status.
// All added records live under a SAVEPOINT and are rolled back.
func proveSelectiveUSNPostgres18Outcome(
    t *testing.T,ctx context.Context,tx pgx.Tx,
    signedGenerationID int64,originalRecordID int64,
) {
    t.Helper()
    if _,err:=tx.Exec(ctx,"SAVEPOINT fi_selective_observation_proof");err!=nil{t.Fatal(err)}
    defer func(){
        if _,err:=tx.Exec(context.Background(),"ROLLBACK TO SAVEPOINT fi_selective_observation_proof");err!=nil{
            t.Fatal("disposable PostgreSQL18 selective outcome savepoint: ",err)
        }
    }()
    var batchID int64
    if err:=tx.QueryRow(ctx,`
SELECT source_batch_id
FROM fi.source_record
WHERE source_record_id=$1
`,originalRecordID).Scan(&batchID);err!=nil{t.Fatal(err)}
    payload:=testUSNSelectiveSourceOutcome()
    // The source fixture uses a fresh timestamp for each signed record.
    // Bind the independently observed outcome to the EXACT original
    // already-projected USN source, not a new logically similar batch.
    if err:=tx.QueryRow(ctx,`
SELECT encode(source_batch_sha256,'hex')
FROM fi.usn_scoped_capture
WHERE source_record_id=$1
`,originalRecordID).Scan(&payload.SourceBatchSHA256);err!=nil{
        t.Fatalf("lookup exact original signed USN source SHA-256: %v",err)
    }
    digest:=sha256.Sum256([]byte("fi real postgres18 independently observed outcome fixture"))
    var observedRecordID int64
    err:=tx.QueryRow(ctx,`
INSERT INTO fi.source_record(
 source_batch_id,record_ordinal,version,record_kind,scope_id,
 written_at,record_bytes,record_sha256,ingest_version)
VALUES ($1,2,$2,'USNSelectiveObservation',$3,$4,512,$5,$6)
RETURNING source_record_id
`,batchID,SpoolRecordVersion,payload.GovernedScopeID,time.Now().UTC(),
        digest[:],IngestVersion).Scan(&observedRecordID)
    if err!=nil{t.Fatalf("create disposable signed selective source: %v",err)}

    if err:=projectUSNSelectiveObservation(ctx,tx,"ci-disposable-usn-source",
        observedRecordID,payload.GovernedScopeID,payload);err!=nil{
        t.Fatalf("real postgres18 source-bound selective outcome rejected: %v",err)
    }
    if err:=verifyUSNSelectiveObservationsComplete(ctx,tx,signedGenerationID);err!=nil{
        t.Fatalf("independent B could not verify exact source-bound outcome: %v",err)
    }
    var status,reason string
    var triggers int64
    err=tx.QueryRow(ctx,`
SELECT o.observation_status,o.reason_code,count(t.trigger_ordinal)
FROM fi.usn_selective_observation o
JOIN fi.usn_selective_observation_trigger t ON t.source_record_id=o.source_record_id
WHERE o.source_record_id=$1
GROUP BY o.observation_status,o.reason_code
`,observedRecordID).Scan(&status,&reason,&triggers)
    if err!=nil||status!="Unavailable"||reason!="OriginalFileIDNoLongerExists"||triggers!=1{
        t.Fatalf("real postgres18 outcome not durable: status=%s reason=%s triggers=%d err=%v",
            status,reason,triggers,err)
    }

    // Not even an exact total can hide a changed historical trigger.
    if _,err:=tx.Exec(ctx,"SAVEPOINT fi_selective_trigger_tamper");err!=nil{t.Fatal(err)}
    if _,err:=tx.Exec(ctx,`
UPDATE fi.usn_selective_observation_trigger SET usn=105
WHERE source_record_id=$1
`,observedRecordID);err!=nil{t.Fatal(err)}
    if err:=verifyUSNSelectiveObservationsComplete(ctx,tx,signedGenerationID);err==nil{
        t.Fatal("independent B accepted forged original NTFS USN trigger")
    }
    if _,err:=tx.Exec(ctx,"ROLLBACK TO SAVEPOINT fi_selective_trigger_tamper");err!=nil{t.Fatal(err)}

    // Database CHECK permits an observed row with booleans; B must require
    // an actual relational NTFS FileObservation, not just a status label.
    if _,err:=tx.Exec(ctx,"SAVEPOINT fi_selective_snapshot_tamper");err!=nil{t.Fatal(err)}
    if _,err:=tx.Exec(ctx,`
UPDATE fi.usn_selective_observation
SET observation_status='Observed',reason_code='',error_text='',
    has_ntfs_observation=true,has_content_hashes=true
WHERE source_record_id=$1
`,observedRecordID);err!=nil{t.Fatal(err)}
    if err:=verifyUSNSelectiveObservationsComplete(ctx,tx,signedGenerationID);err==nil{
        t.Fatal("independent B accepted invented NTFS file/hash observation")
    }
    if _,err:=tx.Exec(ctx,"ROLLBACK TO SAVEPOINT fi_selective_snapshot_tamper");err!=nil{t.Fatal(err)}
    if err:=verifyUSNSelectiveObservationsComplete(ctx,tx,signedGenerationID);err!=nil{
        t.Fatalf("valid original outcome not restored after injection: %v",err)
    }
}
