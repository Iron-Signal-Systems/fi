//go:build fi_typed_chunk_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/jackc/pgx/v5"
)

// Validates the exact typed-buffer -> pgx COPY -> SQL digest round trip
// on two intact original source batches with overlapping record ordinals.
// The fixture exists ONLY in a transaction in a purpose-built PostgreSQL 18
// database; it cannot write authoritative fi.* tables.
func TestBacklogJoinedTypedSourceCopyPostgres(t *testing.T) {
	dsn := os.Getenv("FI_TYPED_CHUNK_PG_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL 18 DSN not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil { t.Fatal(err) }
	defer conn.Close(context.Background())
	var database, user string
	var version int
	var fiExists, recoveryExists bool
	if err := conn.QueryRow(ctx, `SELECT current_database(), current_user,
current_setting('server_version_num')::int,
to_regnamespace('fi') IS NOT NULL, to_regnamespace('fi_recovery') IS NOT NULL`).Scan(
		&database, &user, &version, &fiExists, &recoveryExists,
	); err != nil { t.Fatal(err) }
	if database != "fi_typed_chunks_integration" || user != "fi_typed_test" ||
		version < 180000 || fiExists || recoveryExists {
		t.Fatalf("REFUSE unsafe PostgreSQL target: db=%q user=%q ver=%d fi=%v recovery=%v",
			database,user,version,fiExists,recoveryExists)
	}
	tx, err := conn.Begin(ctx)
	if err != nil { t.Fatal(err) }
	defer tx.Rollback(context.Background())
	for _, ddl := range []string{
		`CREATE SCHEMA fi_recovery`,
		`CREATE TABLE fi_recovery.pending_source_record (
receipt_sha256 bytea NOT NULL,
window_index integer NOT NULL,
batch_index integer NOT NULL,
record_ordinal bigint NOT NULL,
version text NOT NULL,
record_kind text NOT NULL,
scope_id text NOT NULL,
written_at timestamptz NOT NULL,
written_at_original text NOT NULL,
record_bytes integer NOT NULL,
record_sha256 bytea NOT NULL,
PRIMARY KEY(receipt_sha256,batch_index,record_ordinal)
)`,
		`CREATE INDEX pending_source_test_window ON fi_recovery.pending_source_record
(receipt_sha256,window_index,batch_index,record_ordinal)`,
	} {
		if _,err:=tx.Exec(ctx,ddl);err!=nil{t.Fatal(err)}
	}
	var digest [32]byte
	for i:=range digest {digest[i]=byte(i+1)}
	at:=time.Date(2026,11,3,12,34,56,0,time.UTC)
	p:=SourceRecord{
		Record:spool.Record{Version:SpoolRecordVersion,RecordKind:"WindowsSecurityEvent",
			ScopeID:"test-scope",WrittenAt:"2026-11-03T12:34:56.000000000Z"},
		RecordBytes:512,RecordSHA256:hex.EncodeToString(digest[:]),
		WrittenAtUTC:at,
	}
	s:=&joinedBacklogSource{tx:tx,receipt:bytes.Repeat([]byte{0xab},32),
		index:1,descriptor:BacklogCheckpointDescriptor{StartBatch:4,EndBatch:6},
		chunkRows:32768,digest:sha256.New(),families:make(map[string]uint64)}
	for _,batchIndex:=range []int{4,5} {
		s.batchIndex=batchIndex
		dec:=append([]byte(nil),digest[:]...)
		if err:=s.addPrepared(ctx,1,p,dec);err!=nil{t.Fatal(err)}
		dec[0] ^= 0xff
	}
	if err:=s.flush(ctx);err!=nil{t.Fatal(err)}
	if len(s.rows)!=0 || s.copyCalls!=1 {
		t.Fatalf("COPY didn't flush exactly two source batches: remaining=%d calls=%d",len(s.rows),s.copyCalls)
	}
	sqlDigest,records,sourceBytes,err:=hashBacklogDatabaseSourceRows(ctx,tx,s.receipt,s.index)
	if err!=nil{t.Fatal(err)}
	if records!=2 || sourceBytes!=1024 || !bytes.Equal(sqlDigest,s.digest.Sum(nil)) {
		t.Fatalf("source COPY identity/hash mismatch: records=%d bytes=%d",records,sourceBytes)
	}
	for _,batchIndex:=range []int{4,5} {
		var ordinal int64
		var stored []byte
		if err:=tx.QueryRow(ctx,`SELECT record_ordinal, record_sha256
FROM fi_recovery.pending_source_record
WHERE receipt_sha256=$1 AND window_index=1 AND batch_index=$2`,
			s.receipt,batchIndex).Scan(&ordinal,&stored);err!=nil {t.Fatal(err)}
		if ordinal!=1 || !bytes.Equal(stored,digest[:]) {
			t.Fatalf("original signed source key or digest changed in batch %d",batchIndex)
		}
	}
	t.Log("PASS: same-ordinal cross-signed-batch SQL round trip and exact source digest")
}
