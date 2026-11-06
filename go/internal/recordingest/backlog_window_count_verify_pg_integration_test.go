//go:build fi_typed_chunk_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "os"
    "testing"
    "time"
    "github.com/jackc/pgx/v5"
)

// TestPrivateIndexedCountVerificationPostgres creates only an isolated, fully
// rolled-back shadow schema. It exercises the actual legacy and private LATERAL
// verifier through privateProjectionTx, including failed count/byte gates.
func TestPrivateIndexedCountVerificationPostgres(t *testing.T) {
    dsn := os.Getenv("FI_TYPED_CHUNK_PG_DSN")
    if dsn == "" { t.Skip("isolated PostgreSQL DSN unavailable") }
    ctx,cancel := context.WithTimeout(context.Background(),60*time.Second)
    defer cancel()
    conn,err := pgx.Connect(ctx,dsn)
    if err!=nil {t.Fatal(err)}
    defer conn.Close(context.Background())
    var db,user string
    var version int
    var fiExists,recoveryExists,shadowExists bool
    if err:=conn.QueryRow(ctx,`SELECT current_database(),current_user,current_setting('server_version_num')::int,
        to_regnamespace('fi') IS NOT NULL,to_regnamespace('fi_recovery') IS NOT NULL,
        to_regnamespace('fi_recovery_projection') IS NOT NULL`).Scan(
        &db,&user,&version,&fiExists,&recoveryExists,&shadowExists);err!=nil {t.Fatal(err)}
    if db!="fi_typed_chunks_integration"||user!="fi_typed_test"||version<180000||fiExists||recoveryExists||shadowExists {
        t.Fatalf("REFUSE unsafe private indexed verifier DB=%q user=%q version=%d fi=%t recovery=%t shadow=%t",
            db,user,version,fiExists,recoveryExists,shadowExists)
    }
    tx,err:=conn.Begin(ctx)
    if err!=nil{t.Fatal(err)}
    defer tx.Rollback(context.Background())
    for _,stmt:=range []string{
        `CREATE SCHEMA fi_recovery_projection`,
        `CREATE TABLE fi_recovery_projection.source_batch(
            source_batch_id bigint PRIMARY KEY,
            recorded_generation_id bigint NOT NULL,
            batch_id text NOT NULL,
            UNIQUE(recorded_generation_id,batch_id))`,
        `CREATE TABLE fi_recovery_projection.source_record(
            source_record_id bigint PRIMARY KEY,
            source_batch_id bigint NOT NULL REFERENCES fi_recovery_projection.source_batch,
            record_ordinal bigint NOT NULL,
            record_bytes integer NOT NULL,
            UNIQUE(source_batch_id,record_ordinal))`,
        `INSERT INTO fi_recovery_projection.source_batch VALUES
            (101,7,'signed-01'),(102,7,'signed-02'),(103,7,'unselected'),(201,8,'signed-01')`,
        `INSERT INTO fi_recovery_projection.source_record VALUES
            (1,101,1,100),(2,101,2,101),(3,102,1,200),(4,102,2,201),
            (5,103,1,999),(6,201,1,888)`,
    } {if _,err:=tx.Exec(ctx,stmt);err!=nil{t.Fatalf("fixture: %v",err)}}
    privateTx:=privateProjectionTx{Tx:tx}
    batches:=[]PreparedBatch{{BatchID:"signed-01"},{BatchID:"signed-02"}}
    legacyCtx:=context.Background()
    indexedCtx:=WithPrivateIndexedWindowCountVerify(legacyCtx)
    require := func(name string,expectOK bool,rows,bytes int64) {
        t.Helper()
        for _,candidate:=range []struct{name string;ctx context.Context}{
            {"legacy",legacyCtx},{"indexed",indexedCtx},
        } {
            err:=verifyBacklogShadowWindowCounts(candidate.ctx,privateTx,7,batches,rows,bytes)
            if expectOK && err!=nil {t.Errorf("%s %s unexpected verification rejection: %v",name,candidate.name,err)}
            if !expectOK && err==nil {t.Errorf("%s %s accepted mismatched signed evidence",name,candidate.name)}
        }
    }
    require("exact signed window",true,4,602)
    require("incorrect record count",false,5,602)
    require("incorrect signed bytes",false,4,603)
    // Modify one row inside a savepoint; both variants must refuse corrupted
    // bytes and the original rows must be fully restored.
    if _,err:=tx.Exec(ctx,"SAVEPOINT bad_bytes");err!=nil{t.Fatal(err)}
    if _,err:=tx.Exec(ctx,`UPDATE fi_recovery_projection.source_record SET record_bytes=record_bytes+1
          WHERE source_record_id=4`);err!=nil{t.Fatal(err)}
    require("altered stored byte count",false,4,602)
    if _,err:=tx.Exec(ctx,"ROLLBACK TO SAVEPOINT bad_bytes");err!=nil{t.Fatal(err)}
    require("restored bytes",true,4,602)
    if _,err:=tx.Exec(ctx,"SAVEPOINT missing_row");err!=nil{t.Fatal(err)}
    if _,err:=tx.Exec(ctx,`DELETE FROM fi_recovery_projection.source_record WHERE source_record_id=4`);err!=nil{t.Fatal(err)}
    require("missing source row",false,4,602)
    if _,err:=tx.Exec(ctx,"ROLLBACK TO SAVEPOINT missing_row");err!=nil{t.Fatal(err)}
    require("restored missing row",true,4,602)
    if err:=tx.Rollback(ctx);err!=nil{t.Fatal(err)}
    var exists bool
    if err:=conn.QueryRow(ctx,`SELECT to_regnamespace('fi_recovery_projection') IS NOT NULL`).Scan(&exists);err!=nil {t.Fatal(err)}
    if exists {t.Fatal("rollback leaked experimental shadow schema")}
}
