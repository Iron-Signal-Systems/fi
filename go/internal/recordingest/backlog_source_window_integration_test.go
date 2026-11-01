//go:build freebsd && fi_backlog_source_window_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, in the repository root LICENSE file.

package recordingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/jackc/pgx/v5"
)

//go:embed backlog_artifact_ledger_schema.sql
var backlogSourceWindowSchema string

func backlogSourceWindowFixture(t *testing.T, counts []int, lateInvalid bool) *PreparedGeneration {
	t.Helper()
	g:=backlogWindowFixture(counts,1)
	g.Receipt.Descriptor.SourceID="fi-source-window-acceptance.iss.local"
	g.Receipt.Descriptor.GenerationID="20261101T125000.000000000Z-fi-stage"
	g.ReceiptSHA256=strings.Repeat("a",64)
	g.Receipt.TransferSHA256=strings.Repeat("b",64)
	if lateInvalid {
		g.Receipt.Descriptor.SourceID="fi-source-window-late-reject.iss.local"
		g.Receipt.Descriptor.GenerationID="20261101T125100.000000000Z-fi-stage"
		g.ReceiptSHA256=strings.Repeat("c",64)
		g.Receipt.TransferSHA256=strings.Repeat("d",64)
	}
	g.Receipt.DataBytes=0
	for batchIndex:=range g.Batches {
		b:=&g.Batches[batchIndex]
		var raw []byte
		for i:=0;i<counts[batchIndex];i++{
			record:=spool.Record{
				Version:SpoolRecordVersion,
				RecordKind:"NTFSCollectionError",
				ScopeID:fmt.Sprintf("fi-recovery-window-%d",batchIndex),
				WrittenAt:"2026-11-01T12:00:00.123456789Z",
				Payload:json.RawMessage(`{"synthetic":true}`),
			}
			if lateInvalid && batchIndex==len(counts)-1 && i==0 {
				record.Version="malformed-fi-version"
			}
			encoded,err:=json.Marshal(record)
			if err!=nil{t.Fatal(err)}
			raw=append(raw,encoded...)
			raw=append(raw,'\n')
		}
		path:=filepath.Join(t.TempDir(),fmt.Sprintf("batch-%d.jsonl",batchIndex))
		if err:=os.WriteFile(path,raw,0600);err!=nil{t.Fatal(err)}
		digest:=sha256.Sum256(raw)
		b.DataPath=path
		b.Manifest.DataBytes=int64(len(raw))
		b.Manifest.DataSHA256=hex.EncodeToString(digest[:])
		b.Manifest.Version=spool.ManifestVersion
		b.Manifest.CreatedAt="2026-11-01T11:59:00Z"
		b.Manifest.CompletedAt="2026-11-01T12:00:00Z"
		manifestRaw,err:=json.Marshal(b.Manifest)
		if err!=nil{t.Fatal(err)}
		b.ManifestRawBytes=manifestRaw
		manifestDigest:=sha256.Sum256(b.ManifestRawBytes)
		b.ManifestSHA256=hex.EncodeToString(manifestDigest[:])
		g.Receipt.DataBytes+=uint64(len(raw))
	}
	return g
}

func TestBacklogSourceWindowIsolatedPostgresAcceptance(t *testing.T) {
	if os.Getenv("FI_M1_ALLOW_ISOLATED_WRITES")!="1"{
		t.Skip("isolated PostgreSQL source-window fixture disabled")
	}
	root:=filepath.Join(os.Getenv("HOME"),"fi-m1-postgres-20261012")
	if os.Getenv("FI_M1_TEST_POSTGRES_ROOT")!=root {
		t.Fatal("STOP: isolated PostgreSQL fixture path mismatch")
	}
	version,err:=os.ReadFile(filepath.Join(root,"data","PG_VERSION"))
	if err!=nil || string(version)!="18\n" {
		t.Fatal("STOP: PostgreSQL 18 fixture marker missing")
	}
	ctx,cancel:=context.WithTimeout(context.Background(),3*time.Minute)
	defer cancel()
	dsn:=func(user string)string {
		return fmt.Sprintf("host=%s port=55418 user=%s dbname=fi sslmode=disable connect_timeout=3",
			filepath.Join(root,"socket"),user)
	}
	admin,err:=pgx.Connect(ctx,dsn("fi_m1_admin"))
	if err!=nil{t.Fatal(err)}
	t.Cleanup(func(){_ = admin.Close(context.Background())})
	conn,err:=pgx.Connect(ctx,dsn("fi_ingest"))
	if err!=nil{t.Fatal(err)}
	t.Cleanup(func(){_ = conn.Close(context.Background())})
	for _,p:=range []struct{c *pgx.Conn;want string}{
		{admin,"fi_m1_admin"},{conn,"fi_ingest"},
	}{
		var user,db,port,version string
		if err:=p.c.QueryRow(ctx,`SELECT current_user,current_database(),
			current_setting('port'),current_setting('server_version_num')`).
			Scan(&user,&db,&port,&version);err!=nil{t.Fatal(err)}
		if user!=p.want||db!="fi"||port!="55418"||!strings.HasPrefix(version,"18"){
			t.Fatalf("STOP: unexpected PostgreSQL server %s %s %s %s",user,db,port,version)
		}
	}
	var dataDir string
	if err:=admin.QueryRow(ctx,"SELECT current_setting('data_directory')").Scan(&dataDir);err!=nil{t.Fatal(err)}
	if filepath.Clean(dataDir)!=filepath.Join(root,"data"){t.Fatalf("STOP: wrong data directory %s",dataDir)}
	var schemaPresent bool
	if err:=admin.QueryRow(ctx,"SELECT to_regnamespace('fi_recovery') IS NOT NULL").Scan(&schemaPresent);err!=nil{t.Fatal(err)}
	if schemaPresent{t.Fatal("STOP: refuse existing private recovery schema")}
	g:=backlogSourceWindowFixture(t,[]int{3,3,3},false)
	var oldRows int64
	if err:=admin.QueryRow(ctx,"SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1",g.Receipt.Descriptor.SourceID).Scan(&oldRows);err!=nil{t.Fatal(err)}
	if oldRows!=0{t.Fatal("STOP: original test source already exists in authoritative SoR")}
	if _,err:=admin.Exec(ctx,backlogSourceWindowSchema,pgx.QueryExecModeSimpleProtocol);err!=nil{t.Fatal(err)}
	t.Cleanup(func(){
		c,done:=context.WithTimeout(context.Background(),30*time.Second);defer done()
		if _,err:=admin.Exec(c,"DROP SCHEMA fi_recovery CASCADE");err!=nil{
			t.Errorf("isolated recovery schema cleanup failed: %v",err)
		}
	})
	var update,deleteRows,truncate bool
	if err:=conn.QueryRow(ctx,`
SELECT has_table_privilege(current_user,'fi_recovery.pending_source_record','UPDATE'),
       has_table_privilege(current_user,'fi_recovery.pending_source_record','DELETE'),
       has_table_privilege(current_user,'fi_recovery.pending_source_record','TRUNCATE')
`).Scan(&update,&deleteRows,&truncate);err!=nil{t.Fatal(err)}
	if update||deleteRows||truncate{t.Fatal("STOP: runtime has destructive recovery row privilege")}

	privateRoot:=privateBacklogTestRoot(t)
	lim:=BacklogWindowLimits{MaxRecords:6,MaxDataBytes:1<<20}
	for i:=0;i<2;i++{
		if _,err:=MaterializeBacklogWindow(ctx,g,lim,i,privateRoot);err!=nil{t.Fatal(err)}
		if err:=RecordVerifiedBacklogArtifactWindow(ctx,conn,g,lim,i,privateRoot);err!=nil{t.Fatal(err)}
	}
	if err:=StageVerifiedBacklogSourceWindow(ctx,conn,g,lim,1,privateRoot);err==nil{
		t.Fatal("source window 1 accepted without source window 0")
	}
	if _,err:=ReplayVerifiedBacklogSourceWindow(ctx,conn,g,lim,1,privateRoot,
		func(_ int,_ int64,_ SourceRecord)error{
			t.Fatal("incomplete window unexpectedly reached projection visitor")
			return nil
		});err==nil{
		t.Fatal("missing private source-window marker was accepted by projection replay")
	}
	if err:=StageVerifiedBacklogSourceWindow(ctx,conn,g,lim,0,privateRoot);err!=nil{t.Fatal(err)}
	// Drop the connection to prove the transaction's durable committed state.
	if err:=conn.Close(ctx);err!=nil{t.Fatal(err)}
	conn,err=pgx.Connect(ctx,dsn("fi_ingest"))
	if err!=nil{t.Fatal(err)}
	if err:=StageVerifiedBacklogSourceWindow(ctx,conn,g,lim,0,privateRoot);err!=nil{
		t.Fatalf("verified source-window replay should be idempotent: %v",err)
	}
	if err:=StageVerifiedBacklogSourceWindow(ctx,conn,g,lim,1,privateRoot);err!=nil{t.Fatal(err)}
	// Replay window 0 after reconnect. Envelopes must be delivered in the
	// exact two-batch / three-ordinal sequence from the signed source.
	var delivered []string
	stats,err:=ReplayVerifiedBacklogSourceWindow(ctx,conn,g,lim,0,privateRoot,
		func(batchIndex int,ordinal int64,record SourceRecord)error{
			if record.Record.RecordKind!="NTFSCollectionError"||record.RecordSHA256==""{
				t.Fatal("replay record identity invalid")
			}
			delivered=append(delivered,fmt.Sprintf("%d/%d",batchIndex,ordinal))
			return nil
		})
	if err!=nil{t.Fatal(err)}
	if stats.BatchCount!=2||stats.RecordCount!=6||stats.DataBytes==0||
		strings.Join(delivered,",")!="0/1,0/2,0/3,1/1,1/2,1/3"{
		t.Fatalf("incorrect ordered projection input: %+v delivered=%v",stats,delivered)
	}
	if _,err:=ReplayVerifiedBacklogSourceWindow(ctx,conn,g,lim,0,privateRoot,
		func(_ int,_ int64,_ SourceRecord)error{return fmt.Errorf("injected downstream rejection")});err==nil{
		t.Fatal("downstream visitor failure was lost")
	}
	var sourceRows,markers,authoritative,authoritativeRows int64
	if err:=conn.QueryRow(ctx,`
SELECT
 (SELECT count(*) FROM fi_recovery.pending_source_record WHERE receipt_sha256=decode($1,'hex')),
 (SELECT count(*) FROM fi_recovery.source_window WHERE receipt_sha256=decode($1,'hex')),
 (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$2),
 (SELECT count(*) FROM fi.source_record sr
    JOIN fi.source_batch sb ON sr.source_batch_id=sb.source_batch_id
    JOIN fi.recorded_generation rg ON sb.recorded_generation_id=rg.recorded_generation_id
    WHERE rg.source_id=$2)
`,g.ReceiptSHA256,g.Receipt.Descriptor.SourceID).Scan(&sourceRows,&markers,&authoritative,&authoritativeRows);err!=nil{t.Fatal(err)}
	if sourceRows!=9||markers!=2||authoritative!=0||authoritativeRows!=0{
		t.Fatalf("STOP: source stage %d rows %d markers, authoritative generations %d rows %d",
			sourceRows,markers,authoritative,authoritativeRows)
	}
	// Completed window may not be trusted merely because a SQL marker exists.
	d,err:=DescribeBacklogWindows(g,lim);if err!=nil{t.Fatal(err)}
	tamper:=filepath.Join(privateRoot,"receipt-"+d[0].ReceiptSHA256,"window-00000000","batch-00000000.data")
	original,err:=os.ReadFile(tamper);if err!=nil{t.Fatal(err)}
	original[0]='x'
	if err:=os.WriteFile(tamper,original,0600);err!=nil{t.Fatal(err)}
	if err:=StageVerifiedBacklogSourceWindow(ctx,conn,g,lim,0,privateRoot);err==nil{
		t.Fatal("tampered staged source was accepted on replay")
	}
	if _,err:=ReplayVerifiedBacklogSourceWindow(ctx,conn,g,lim,0,privateRoot,
		func(_ int,_ int64,_ SourceRecord)error{
			t.Fatal("tampered source was delivered to projection visitor")
			return nil
		});err==nil{
		t.Fatal("tampered private source was replayed")
	}
	// Late malformed source envelope after an earlier 1024-row COPY must
	// roll back its entire window, including all previously copied rows.
	late:=backlogSourceWindowFixture(t,[]int{1100,1},true)
	lateRoot:=privateBacklogTestRoot(t)
	lateLim:=BacklogWindowLimits{MaxRecords:1200,MaxDataBytes:1<<20}
	if _,err:=MaterializeBacklogWindow(ctx,late,lateLim,0,lateRoot);err!=nil{t.Fatal(err)}
	if err:=RecordVerifiedBacklogArtifactWindow(ctx,conn,late,lateLim,0,lateRoot);err!=nil{t.Fatal(err)}
	if err:=StageVerifiedBacklogSourceWindow(ctx,conn,late,lateLim,0,lateRoot);err==nil{
		t.Fatal("late invalid spool envelope was accepted")
	}
	var leaked,completed int64
	if err:=conn.QueryRow(ctx,`
SELECT (SELECT count(*) FROM fi_recovery.pending_source_record WHERE receipt_sha256=decode($1,'hex')),
       (SELECT count(*) FROM fi_recovery.source_window WHERE receipt_sha256=decode($1,'hex'))
`,late.ReceiptSHA256).Scan(&leaked,&completed);err!=nil{t.Fatal(err)}
	if leaked!=0||completed!=0{
		t.Fatalf("STOP: late invalid record escaped transaction rollback rows=%d markers=%d",leaked,completed)
	}
	t.Log("PASS: authenticated source envelopes, window restart/replay, atomic rollback after COPY, zero SoR publication")
}
