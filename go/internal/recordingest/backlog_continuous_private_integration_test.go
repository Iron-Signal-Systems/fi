//go:build freebsd && fi_backlog_typed_window_integration && fi_copy_latency_replay_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
 "context"
 "fmt"
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/jackc/pgx/v5"
)

// TestBacklogContinuousPrivateFullTransferAfterResume verifies the new
// callback-driven private projection path against a REAL signed/recorded FIGT
// fixture. It uses the disposable isolated PostgreSQL 18 test instance only.
//
// Acceptance: first private window committed using the prior loader;
// continuous resume verifies the complete signed transfer and all remaining
// private typed windows; every source row is present in private shadow;
// canonical FI and Accepted journal are unchanged.
func TestBacklogContinuousPrivateFullTransferAfterResume(t *testing.T){
 if os.Getenv("FI_M1_ALLOW_ISOLATED_WRITES")!="1"{t.Skip("isolated PostgreSQL fixture not enabled")}
 root:=filepath.Join(os.Getenv("HOME"),"fi-m1-postgres-20261012")
 if os.Getenv("FI_M1_TEST_POSTGRES_ROOT")!=root{t.Fatal("STOP: unexpected isolated PostgreSQL root")}
 version,err:=os.ReadFile(filepath.Join(root,"data","PG_VERSION"))
 if err!=nil||string(version)!="18\n"{t.Fatal("STOP: isolated PostgreSQL 18 root unavailable")}
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Minute)
 defer cancel()
 ctx,err:=WithFixedSecurityBulkProfile(ctx,"P3")
 if err!=nil{t.Fatal(err)}
 connect:=func(user string)string{return fmt.Sprintf(
  "host=%s port=55418 user=%s dbname=fi sslmode=disable connect_timeout=3",
  filepath.Join(root,"socket"),user)}
 admin,err:=pgx.Connect(ctx,connect("fi_m1_admin"));if err!=nil{t.Fatal(err)}
 t.Cleanup(func(){_ = admin.Close(context.Background())})
 writer,err:=pgx.Connect(ctx,connect("fi_ingest"));if err!=nil{t.Fatal(err)}
 t.Cleanup(func(){_ = writer.Close(context.Background())})
 reader,err:=pgx.Connect(ctx,connect("fi_ingest"));if err!=nil{t.Fatal(err)}
 t.Cleanup(func(){_ = reader.Close(context.Background())})
 for _,c:=range []struct{conn *pgx.Conn; role string}{{admin,"fi_m1_admin"},{writer,"fi_ingest"},{reader,"fi_ingest"}}{
  var who,db,port string
  if err:=c.conn.QueryRow(ctx,"SELECT current_user,current_database(),current_setting('port')").Scan(&who,&db,&port);err!=nil{t.Fatal(err)}
  if who!=c.role||db!="fi"||port!="55418"{t.Fatalf("STOP: unexpected isolated SQL identity %s/%s/%s",who,db,port)}
 }
 var present bool
 if err:=admin.QueryRow(ctx,`SELECT
  (to_regnamespace('fi_recovery') IS NOT NULL OR
  to_regnamespace('fi_recovery_projection') IS NOT NULL)`).Scan(&present);err!=nil{t.Fatal(err)}
 if present{t.Fatal("STOP: recovery schemas already exist, fixture not isolated")}
 if _,err:=admin.Exec(ctx,isolatedTypedWindowSchema,pgx.QueryExecModeSimpleProtocol);err!=nil{t.Fatal(err)}
 t.Cleanup(func(){
  cleanup,done:=context.WithTimeout(context.Background(),30*time.Second)
  defer done()
  if _,err:=admin.Exec(cleanup,"DROP SCHEMA fi_recovery CASCADE");err!=nil{t.Errorf("drop test-owned private ledger: %v",err)}
 })
 for i,name:=range []string{"0001_relational.sql","0002_source_families.sql",
  "0003_usn_relational_identity.sql","0004_security_field_name_index.sql",
  "0005_usn_capture_binding.sql"}{
  raw,err:=os.ReadFile(filepath.Join("..","..","..","database","schema",name))
  if err!=nil{t.Fatal(err)}
  ddl,err:=RewritePrivateProjectionMigration(name,string(raw))
  if err!=nil{t.Fatal(err)}
  if _,err:=admin.Exec(ctx,ddl,pgx.QueryExecModeSimpleProtocol);err!=nil{t.Fatalf("install %s: %v",name,err)}
  if i==0{t.Cleanup(func(){
   cleanup,done:=context.WithTimeout(context.Background(),30*time.Second)
   defer done()
   if _,err:=admin.Exec(cleanup,"DROP SCHEMA fi_recovery_projection CASCADE");err!=nil{t.Errorf("drop test-owned private projection: %v",err)}
  })}
 }
 fixture:=t.TempDir()
 for _,p:=range []string{"custody","recorded","ready",
  filepath.Join("recorded","sources",multiBatchSource),
  filepath.Join(multiBatchSource,"frozen"),filepath.Join(multiBatchSource,"sealed")}{
  if err:=os.MkdirAll(filepath.Join(fixture,p),0700);err!=nil{t.Fatal(err)}
 }
 signed,_,_,_,_:=writeMultiBatchSignedGeneration(t,fixture,"observed",64,32)
 config:=GenerationLoadConfig{
  CustodyRoot:filepath.Join(fixture,"custody"),
  RecordedRoot:filepath.Join(fixture,"recorded"),
  SourceID:multiBatchSource,SourceNamespaces:true,
  MaxCanonicalBytes:multiBatchMaxGenerationBytes,
  MaxEncodedBytes:multiBatchMaxGenerationBytes,
  MaxManifestBytes:1<<20,
 }
 trustFn:=func(src string)(generationTrustBundle,error){
  if src!=multiBatchSource{return generationTrustBundle{},fmt.Errorf("unrecognized fixture source")}
  return signed.Trust,nil
 }
 g,err:=loadRecordedGenerationWithTrust(config,signed.GenerationID,trustFn)
 if err!=nil{t.Fatal(err)}
 limits:=BacklogWindowLimits{MaxRecords:32,MaxDataBytes:32<<20}
 windows,err:=DescribeBacklogWindows(g,limits)
 if err!=nil{t.Fatal(err)}
 if len(windows)<2{t.Fatalf("expected multiple signed windows, got %d",len(windows))}
 privateRoot:=privateBacklogTestRoot(t)
 if _,err:=MaterializeBacklogWindow(ctx,g,limits,0,privateRoot);err!=nil{t.Fatal(err)}
 if err:=RecordVerifiedBacklogArtifactWindow(ctx,writer,g,limits,0,privateRoot);err!=nil{t.Fatal(err)}
 if err:=StageVerifiedBacklogSourceWindow(ctx,writer,g,limits,0,privateRoot);err!=nil{t.Fatal(err)}
 if err:=StageBacklogTypedWindow(ctx,reader,writer,g,limits,0,privateRoot);err!=nil{t.Fatal(err)}
 // The first loader must be fully closed before resuming through a fresh
 // custody stream; this exercises the actual restart boundary.
 if err:=g.Close();err!=nil{t.Fatal(err)}
 var progressed []BacklogContinuousProgress
 result,err:=recoverBacklogContinuousPrivateWithTrust(
  ctx,reader,writer,config,signed.GenerationID,limits,privateRoot,1,
  func(p BacklogContinuousProgress){if p.WindowCommitted>=0{progressed=append(progressed,p)}},
  trustFn)
 if err!=nil{t.Fatalf("continuous full signed private recovery: %v",err)}
 if result.Records!=64||result.Windows!=len(windows)||
  result.GenerationID!=signed.GenerationID||result.SourceID!=multiBatchSource||
  len(progressed)!=len(windows)-1 {
  t.Fatalf("continuous private outcome wrong: result=%+v markers=%d want=%d",result,len(progressed),len(windows)-1)
 }
 var privateRows,accepted,canonical int64
 err=writer.QueryRow(ctx,`SELECT
  (SELECT count(*) FROM fi_recovery_projection.source_record),
  (SELECT count(*) FROM fi.ingest_journal WHERE source_id=$1 AND outcome='Accepted'),
  (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2)
 `,multiBatchSource,signed.GenerationID).Scan(&privateRows,&accepted,&canonical)
 if err!=nil{t.Fatal(err)}
 if privateRows!=64||accepted!=0||canonical!=0{
  t.Fatalf("private rows=%d Accepted=%d canonical=%d",privateRows,accepted,canonical)
 }
 if !strings.EqualFold(result.ReceiptSHA256,g.ReceiptSHA256){t.Fatal("signed receipt digest changed")}
 t.Logf("PASS: resumed signed single-pass private recovery windows=%d records=%d commits=%d canonical=0 Accepted=0",
  result.Windows,result.Records,len(progressed))
}
