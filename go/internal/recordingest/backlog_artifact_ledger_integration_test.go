//go:build freebsd && fi_backlog_artifact_ledger_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, in the repository root LICENSE file.

package recordingest

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

//go:embed backlog_artifact_ledger_schema.sql
var backlogArtifactLedgerFixtureDDL string

// TestBacklogArtifactLedgerIsolatedAcceptance may write ONLY to the isolated
// PostgreSQL 18 fixture at the exact M1 location and port. Production does
// not install this experimental recovery schema.
func TestBacklogArtifactLedgerIsolatedAcceptance(t *testing.T) {
	if os.Getenv("FI_M1_ALLOW_ISOLATED_WRITES")!="1" {
		t.Skip("isolated PostgreSQL artifact-ledger fixture not enabled")
	}
	root:=filepath.Join(os.Getenv("HOME"),"fi-m1-postgres-20261012")
	if os.Getenv("FI_M1_TEST_POSTGRES_ROOT")!=root {
		t.Fatal("STOP: isolated PostgreSQL test root mismatch")
	}
	version,err:=os.ReadFile(filepath.Join(root,"data","PG_VERSION"))
	if err!=nil||string(version)!="18\n" {t.Fatal("STOP: isolated PostgreSQL 18 marker missing")}

	ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second)
	defer cancel()
	connect:=func(user string)string {
		return fmt.Sprintf("host=%s port=55418 user=%s dbname=fi sslmode=disable connect_timeout=3",
			filepath.Join(root,"socket"),user)
	}
	admin,err:=pgx.Connect(ctx,connect("fi_m1_admin"))
	if err!=nil{t.Fatal(err)}
	t.Cleanup(func(){ _ = admin.Close(context.Background()) })
	runtime,err:=pgx.Connect(ctx,connect("fi_ingest"))
	if err!=nil{t.Fatal(err)}
	t.Cleanup(func(){ _ = runtime.Close(context.Background()) })

	for _,item:=range []struct{conn *pgx.Conn;user string}{
		{admin,"fi_m1_admin"},{runtime,"fi_ingest"},
	}{
		var who,db,port,pgVersion string
		if err:=item.conn.QueryRow(ctx,`
SELECT current_user, current_database(),
       current_setting('port'), current_setting('server_version_num')
`).Scan(&who,&db,&port,&pgVersion);err!=nil{t.Fatal(err)}
		if who!=item.user||db!="fi"||port!="55418"||!strings.HasPrefix(pgVersion,"18"){
			t.Fatalf("STOP: wrong isolated fixture identity user=%s db=%s port=%s version=%s",who,db,port,pgVersion)
		}
	}
	var dataDirectory string
	if err:=admin.QueryRow(ctx,"SELECT current_setting('data_directory')").Scan(&dataDirectory);err!=nil{t.Fatal(err)}
	if filepath.Clean(dataDirectory)!=filepath.Join(root,"data"){
		t.Fatalf("STOP: PostgreSQL data_directory mismatch: %s",dataDirectory)
	}
	var exists bool
	if err:=admin.QueryRow(ctx,"SELECT to_regnamespace('fi_recovery') IS NOT NULL").Scan(&exists);err!=nil{t.Fatal(err)}
	if exists{t.Fatal("STOP: existing fi_recovery schema must not be overwritten, dropped, or reused")}
	if _,err:=admin.Exec(ctx,backlogArtifactLedgerFixtureDDL,pgx.QueryExecModeSimpleProtocol);err!=nil{t.Fatal(err)}
	t.Cleanup(func(){
		cleanupCtx,cleanupCancel:=context.WithTimeout(context.Background(),30*time.Second)
		defer cleanupCancel()
		if _,err:=admin.Exec(cleanupCtx,"DROP SCHEMA fi_recovery CASCADE");err!=nil{
			t.Errorf("isolated test-owned schema cleanup failed: %v",err)
		}
	})

	var updates,deletes,truncates bool
	err=runtime.QueryRow(ctx,`
SELECT
 has_table_privilege(current_user,'fi_recovery.verified_artifact_window','UPDATE'),
 has_table_privilege(current_user,'fi_recovery.verified_artifact_window','DELETE'),
 has_table_privilege(current_user,'fi_recovery.verified_artifact_window','TRUNCATE')
`).Scan(&updates,&deletes,&truncates)
	if err!=nil{t.Fatal(err)}
	if updates||deletes||truncates{t.Fatal("STOP: ingest runtime has destructive authority over private recovery ledger")}

	g:=privateBacklogStageFixture(t)
	privateRoot:=privateBacklogTestRoot(t)
	limits:=BacklogWindowLimits{MaxRecords:6,MaxDataBytes:32}
	for _,i:=range []int{0,1}{
		if _,err:=MaterializeBacklogWindow(ctx,g,limits,i,privateRoot);err!=nil{t.Fatal(err)}
	}

	// No record is allowed to skip the first verified window.
	if err:=RecordVerifiedBacklogArtifactWindow(ctx,runtime,g,limits,1,privateRoot);err==nil {
		t.Fatal("unverified missing preceding ledger checkpoint was accepted")
	}
	if err:=RecordVerifiedBacklogArtifactWindow(ctx,runtime,g,limits,0,privateRoot);err!=nil{t.Fatal(err)}

	// Restart the DB connection between window commits, exercising recovery.
	if err:=runtime.Close(ctx);err!=nil{t.Fatal(err)}
	runtime,err=pgx.Connect(ctx,connect("fi_ingest"))
	if err!=nil{t.Fatal(err)}
	if err:=RecordVerifiedBacklogArtifactWindow(ctx,runtime,g,limits,0,privateRoot);err!=nil{
		t.Fatalf("identical durable checkpoint replay must be idempotent: %v",err)
	}
	if err:=RecordVerifiedBacklogArtifactWindow(ctx,runtime,g,limits,1,privateRoot);err!=nil{t.Fatal(err)}

	var persisted,accepted,sourceRows int64
	if err:=runtime.QueryRow(ctx,`
SELECT
 (SELECT count(*) FROM fi_recovery.verified_artifact_window WHERE source_id=$1),
 (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1),
 (SELECT count(*) FROM fi.source_record sr
    JOIN fi.source_batch sb ON sb.source_batch_id=sr.source_batch_id
    JOIN fi.recorded_generation rg ON rg.recorded_generation_id=sb.recorded_generation_id
   WHERE rg.source_id=$1)
`,g.Receipt.Descriptor.SourceID).Scan(&persisted,&accepted,&sourceRows);err!=nil{t.Fatal(err)}
	if persisted!=2||accepted!=0||sourceRows!=0{
		t.Fatalf("STOP: expected 2 private artifact checkpoints and zero authoritative rows, got private=%d accepted=%d source=%d",persisted,accepted,sourceRows)
	}

	// Even a previously committed artifact ledger record never bypasses
	// full hash verification of the actual durable data copy.
	d,err:=DescribeBacklogWindows(g,limits);if err!=nil{t.Fatal(err)}
	tamper:=filepath.Join(privateRoot,"receipt-"+d[0].ReceiptSHA256,"window-00000000","batch-00000000.data")
	if err:=os.WriteFile(tamper,[]byte("tampered"),0600);err!=nil{t.Fatal(err)}
	if err:=RecordVerifiedBacklogArtifactWindow(ctx,runtime,g,limits,0,privateRoot);err==nil{
		t.Fatal("previously committed artifact checkpoint bypassed byte verification")
	}
	if err:=runtime.QueryRow(ctx,
		"SELECT count(*) FROM fi_recovery.verified_artifact_window").Scan(&persisted);err!=nil{t.Fatal(err)}
	if persisted!=2 {t.Fatalf("corruption changed append-only checkpoint count: %d",persisted)}
	t.Log("PASS: restart, idempotent append, strict order, hash rejection, least privilege, SoR untouched")
}
