//go:build freebsd && fi_backlog_typed_window_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// This test runs against the existing disposable PostgreSQL 18 FI fixture.
// A deliberately unique source and attempt are owned and removed by this test;
// it never modifies any actual backlog generation or any other source.
func exerciseBacklogAuthoritativeBridge(t *testing.T,
	ctx context.Context, admin, reader, writer *pgx.Conn) {
	t.Helper()
	source := "fi-private-publish-bridge.iss.local"
	g := privateTypedFixture(t, source, false)
	g.Receipt.Descriptor.GenerationID = "20261101T140000.000000000Z-private-publish-bridge"
	transfer := sha256.Sum256([]byte("fi-private-publish-bridge/transfer/" + source))
	receipt := sha256.Sum256([]byte("fi-private-publish-bridge/receipt/" + source))
	g.Receipt.TransferSHA256 = hex.EncodeToString(transfer[:])
	g.ReceiptSHA256 = hex.EncodeToString(receipt[:])
	attemptID := "fi-private-publish-bridge-20261101"
	limits := BacklogWindowLimits{MaxRecords:3,MaxDataBytes:1<<20}
	root := privateBacklogTestRoot(t)

	// Install cleanup BEFORE any canonical write. Unlike production this
	// disposable test owns both the entire reserved source and its journal.
	// Source tables and journal are deleted only by source and generation,
	// in FK order, in one transaction. No TRUNCATE, CASCADE or schema drop.
	t.Cleanup(func(){
		c,done:=context.WithTimeout(context.Background(),45*time.Second)
		defer done()
		tx,err:=admin.Begin(c)
		if err!=nil{t.Errorf("bridge cleanup begin: %v",err);return}
		defer tx.Rollback(context.Background())
		for _,table:=range []string{"ntfs_collection_error","supporting_source_collection_error"} {
			query:=fmt.Sprintf(`
DELETE FROM fi.%s AS child
USING fi.source_record AS sr, fi.source_batch AS sb, fi.recorded_generation AS rg
WHERE child.source_record_id=sr.source_record_id
  AND sr.source_batch_id=sb.source_batch_id
  AND sb.recorded_generation_id=rg.recorded_generation_id
  AND rg.source_id=$1 AND rg.generation_id=$2
`,table)
			if _,err:=tx.Exec(c,query,source,g.Receipt.Descriptor.GenerationID);err!=nil{
				t.Errorf("bridge cleanup %s: %v",table,err);return
			}
		}
		for _,query:=range []string{
			`DELETE FROM fi.source_record AS sr USING fi.source_batch AS sb,fi.recorded_generation AS rg
WHERE sr.source_batch_id=sb.source_batch_id AND sb.recorded_generation_id=rg.recorded_generation_id
AND rg.source_id=$1 AND rg.generation_id=$2`,
			`DELETE FROM fi.source_batch AS sb USING fi.recorded_generation AS rg
WHERE sb.recorded_generation_id=rg.recorded_generation_id AND rg.source_id=$1 AND rg.generation_id=$2`,
			`DELETE FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2`,
			`DELETE FROM fi.ingest_journal WHERE source_id=$1 AND generation_id=$2 AND attempt_id=$3`,
		}{
			var err error
			if count:=3;count==3 && query==`DELETE FROM fi.ingest_journal WHERE source_id=$1 AND generation_id=$2 AND attempt_id=$3`{
				_,err=tx.Exec(c,query,source,g.Receipt.Descriptor.GenerationID,attemptID)
			}else{
				_,err=tx.Exec(c,query,source,g.Receipt.Descriptor.GenerationID)
			}
			if err!=nil{t.Errorf("bridge cleanup hierarchy: %v",err);return}
		}
		if err:=tx.Commit(c);err!=nil{t.Errorf("bridge cleanup commit: %v",err);return}
		var generations,journal,records int64
		err=admin.QueryRow(c,`
SELECT
 (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1),
 (SELECT count(*) FROM fi.ingest_journal WHERE source_id=$1),
 (SELECT count(*) FROM fi.source_record sr JOIN fi.source_batch sb ON sb.source_batch_id=sr.source_batch_id
  JOIN fi.recorded_generation rg ON rg.recorded_generation_id=sb.recorded_generation_id WHERE rg.source_id=$1)
`,source).Scan(&generations,&journal,&records)
		if err!=nil||generations!=0||journal!=0||records!=0{
			t.Errorf("bridge cleanup verification generations=%d journal=%d source=%d err=%v",generations,journal,records,err)
		}
	})

	// A single staged window cannot start a canonical attempt.
	if _,err:=MaterializeBacklogWindow(ctx,g,limits,0,root);err!=nil{t.Fatal(err)}
	if err:=RecordVerifiedBacklogArtifactWindow(ctx,writer,g,limits,0,root);err!=nil{t.Fatal(err)}
	if err:=StageVerifiedBacklogSourceWindow(ctx,writer,g,limits,0,root);err!=nil{t.Fatal(err)}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,g,limits,0,root);err!=nil{t.Fatal(err)}
	if _,err:=PublishVerifiedBacklogWithAuthoritativeIngest(ctx,reader,writer,g,limits,attemptID);err==nil{
		t.Fatal("partially recovered generation entered canonical publish")
	}
	var incompleteJournal int64
	if err:=writer.QueryRow(ctx,`
SELECT count(*) FROM fi.ingest_journal WHERE attempt_id=$1
`,attemptID).Scan(&incompleteJournal);err!=nil{t.Fatal(err)}
	if incompleteJournal!=0{t.Fatal("incomplete private recovery wrote canonical journal")}

	// Complete private recovery, then invoke the EXISTING canonical transaction.
	if _,err:=RecoverBacklogGenerationToPrivateShadow(ctx,reader,writer,g,limits,root);err!=nil{
		t.Fatalf("finish private recovery: %v",err)
	}
	result,err:=PublishVerifiedBacklogWithAuthoritativeIngest(ctx,reader,writer,g,limits,attemptID)
	if err!=nil{t.Fatalf("atomic authoritative publish: %v",err)}
	if result.Outcome!="Accepted"||result.RecordsCommitted!=6||result.RecordsSeen!=6{
		t.Fatalf("wrong canonical publish result: %+v",result)
	}
	var generations,records,ntfsErrors,supportingErrors,accepted int64
	err=reader.QueryRow(ctx,`
SELECT
 (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2),
 (SELECT count(*) FROM fi.source_record AS sr JOIN fi.source_batch AS sb ON sr.source_batch_id=sb.source_batch_id
  JOIN fi.recorded_generation AS rg ON sb.recorded_generation_id=rg.recorded_generation_id
  WHERE rg.source_id=$1 AND rg.generation_id=$2),
 (SELECT count(*) FROM fi.ntfs_collection_error AS e JOIN fi.source_record AS sr ON e.source_record_id=sr.source_record_id
  JOIN fi.source_batch AS sb ON sr.source_batch_id=sb.source_batch_id
  JOIN fi.recorded_generation AS rg ON sb.recorded_generation_id=rg.recorded_generation_id
  WHERE rg.source_id=$1 AND rg.generation_id=$2),
 (SELECT count(*) FROM fi.supporting_source_collection_error AS e JOIN fi.source_record AS sr ON e.source_record_id=sr.source_record_id
  JOIN fi.source_batch AS sb ON sr.source_batch_id=sb.source_batch_id
  JOIN fi.recorded_generation AS rg ON sb.recorded_generation_id=rg.recorded_generation_id
  WHERE rg.source_id=$1 AND rg.generation_id=$2),
 (SELECT count(*) FROM fi.ingest_journal WHERE attempt_id=$3 AND outcome='Accepted')
`,source,g.Receipt.Descriptor.GenerationID,attemptID).Scan(
		&generations,&records,&ntfsErrors,&supportingErrors,&accepted)
	if err!=nil{t.Fatal(err)}
	if generations!=1||records!=6||ntfsErrors!=3||supportingErrors!=3||accepted!=1{
		t.Fatalf("atomic publish mismatch generation=%d source=%d ntfs=%d support=%d accepted=%d",
			generations,records,ntfsErrors,supportingErrors,accepted)
	}
	// Retry must never duplicate accepted rows or create another journal event.
	replay,err:=PublishVerifiedBacklogWithAuthoritativeIngest(ctx,reader,writer,g,limits,attemptID)
	if err!=nil||replay.Outcome!="AlreadyAccepted"{
		t.Fatalf("canonical retry not idempotent: result=%+v err=%v",replay,err)
	}
	var journal int64
	if err:=reader.QueryRow(ctx,`SELECT count(*) FROM fi.ingest_journal WHERE attempt_id=$1`,attemptID).Scan(&journal);err!=nil{t.Fatal(err)}
	if journal!=2{t.Fatalf("canonical retry added journal event: %d",journal)}
	t.Log("PASS: complete private recovery published atomically through existing canonical ingest; partial refusal, Accepted journal, idempotent replay, isolated cleanup")
}
