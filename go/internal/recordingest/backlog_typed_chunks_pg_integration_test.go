//go:build fi_typed_chunk_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
    "bytes"
    "context"
    "errors"
    "fmt"
    "os"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/jackc/pgx/v5"
)

// Tests on an explicitly named, disposable PostgreSQL 18 database only.
// Everything including test schemas is rolled back. Never connect this test
// to production or any shared FI cluster.
func TestBacklogTypedChunksPostgres(t *testing.T) {
    dsn := os.Getenv("FI_TYPED_CHUNK_PG_DSN")
    if dsn == "" {
        t.Skip("isolated PostgreSQL 18 DSN not configured")
    }
    ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
    defer cancel()
    conn, err := pgx.Connect(ctx, dsn)
    if err != nil { t.Fatal(err) }
    defer conn.Close(context.Background())

    var db, user string
    var version int
    var fiExists bool
    if err := conn.QueryRow(ctx, `SELECT current_database(), current_user,
        current_setting('server_version_num')::int,
        to_regnamespace('fi') IS NOT NULL`).Scan(&db,&user,&version,&fiExists); err != nil { t.Fatal(err) }
    if db != "fi_typed_chunks_integration" || user != "fi_typed_test" || version < 180000 || fiExists {
        t.Fatalf("REFUSE unsafe PostgreSQL destination: db=%q user=%q version=%d existing_fi=%v", db,user,version,fiExists)
    }
    tx, err := conn.Begin(ctx)
    if err != nil { t.Fatal(err) }
    defer tx.Rollback(context.Background())
    for _, ddl := range []string{
        `CREATE SCHEMA fi`,
        `CREATE TABLE fi.source_batch (source_batch_id bigint PRIMARY KEY)`,
        `CREATE TABLE fi.source_record (
            source_record_id bigint GENERATED ALWAYS AS IDENTITY (START WITH 101 INCREMENT BY 7) PRIMARY KEY,
            source_batch_id bigint NOT NULL REFERENCES fi.source_batch,
            record_ordinal bigint NOT NULL,
            version text NOT NULL,
            record_kind text NOT NULL,
            scope_id text NOT NULL,
            written_at timestamptz NOT NULL,
            record_bytes integer NOT NULL,
            record_sha256 bytea NOT NULL CHECK (octet_length(record_sha256)=32),
            ingest_version text NOT NULL,
            UNIQUE (source_batch_id,record_ordinal))`,
        `CREATE TABLE fi.child_marker (
            source_record_id bigint NOT NULL REFERENCES fi.source_record,
            label text NOT NULL)`,
        `INSERT INTO fi.source_batch VALUES (11),(12)`,
    } {
        if _,err := tx.Exec(ctx, ddl); err != nil {t.Fatalf("test schema: %v",err)}
    }
    record := func(batch, ordinal int64) fileSourceBulkRecord {
        return fileSourceBulkRecord{
            sourceBatchID:batch, ordinal:ordinal,
            digest:bytes.Repeat([]byte{byte(batch)},32),
            prepared:SourceRecord{
                Record:spool.Record{Version:SpoolRecordVersion,
                    RecordKind:"FileObservation",ScopeID:"isolated-test"},
                WrittenAtUTC:time.Date(2026,11,2,20,0,0,0,time.UTC),
                RecordBytes:128,
            },
        }
    }
    // Ordinal 1 and 2 repeat in the second original signed batch. A
    // cross-batch mapping keyed only by ordinal would corrupt identity.
    pending := []fileSourceBulkRecord{record(11,1),record(11,2),record(12,1),record(12,2)}
    profile:=&ingestStageProfile{}
    if err := copyFileSourceBulk(ctx,tx,11,pending,profile); err != nil {t.Fatal(err)}
    for i,p := range pending {
        if want:=int64(101+i*7);p.sourceRecordID!=want {
            t.Fatalf("cross-batch parent ID[%d]=%d want %d",i,p.sourceRecordID,want)
        }
        var storedBatch,storedOrdinal int64
        if err := tx.QueryRow(ctx,`SELECT source_batch_id,record_ordinal
            FROM fi.source_record WHERE source_record_id=$1`,p.sourceRecordID).
            Scan(&storedBatch,&storedOrdinal);err!=nil {t.Fatal(err)}
        if storedBatch!=p.sourceBatchID || storedOrdinal!=p.ordinal {
            t.Fatalf("parent key corrupted: (%d,%d) want (%d,%d)",
                storedBatch,storedOrdinal,p.sourceBatchID,p.ordinal)
        }
    }
    // Lookup must fail closed when one requested batch+ordinal pair is absent.
    if _,err:=lookupBulkSourceRecordIDs(ctx,tx,[]int64{11,12},
        []int64{1,999});err==nil {t.Fatal("accepted missing parent mapping")}

    // Simulate a late child-row COPY failure AFTER all source parents were
    // successfully copied. The caller's outer transaction must roll back.
    _,err=tx.CopyFrom(ctx,pgx.Identifier{"fi","child_marker"},
        []string{"source_record_id","label"},pgx.CopyFromRows([][]any{
            {pending[0].sourceRecordID,"valid"},
            {int64(9999999),"broken-reference"},
        }))
    if err==nil {t.Fatal("late child COPY with invalid foreign key succeeded")}
    if rbErr:=tx.Rollback(context.Background());rbErr!=nil && !errors.Is(rbErr,pgx.ErrTxClosed) {
        t.Fatalf("rollback after late COPY failure: %v (original %v)",rbErr,err)
    }
    var exists bool
    if err:=conn.QueryRow(ctx,`SELECT to_regclass('fi.source_record') IS NOT NULL`).Scan(&exists);err!=nil {
        t.Fatal(fmt.Errorf("post-rollback probe: %w",err))
    }
    if exists {t.Fatal("failed window leaked private source rows or schema")}
}
