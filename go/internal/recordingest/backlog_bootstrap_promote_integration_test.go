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
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 "github.com/jackc/pgx/v5"
)

// Correctness gate for server-side private -> canonical copy. This creates
// only a six-record test-owned generation in the isolated PostgreSQL 18
// fixture; it is not a performance claim or substitute for signed real data.
func TestBacklogBootstrapPromoteToEmptyCanonicalPostgres(t *testing.T){
 if os.Getenv("FI_M1_ALLOW_ISOLATED_WRITES")!="1" {t.Skip("isolated PostgreSQL fixture disabled")}
 root:=filepath.Join(os.Getenv("HOME"),"fi-m1-postgres-20261012")
 if os.Getenv("FI_M1_TEST_POSTGRES_ROOT")!=root {t.Fatal("STOP: isolated root mismatch")}
 pgVersion,err:=os.ReadFile(filepath.Join(root,"data","PG_VERSION"))
 if err!=nil || string(pgVersion)!="18\n" {t.Fatal("STOP: PostgreSQL 18 fixture unavailable")}
 ctx,done:=context.WithTimeout(context.Background(),5*time.Minute);defer done()
 connect:=func(user string)string{return fmt.Sprintf("host=%s port=55418 user=%s dbname=fi sslmode=disable connect_timeout=3",filepath.Join(root,"socket"),user)}
 admin,err:=pgx.Connect(ctx,connect("fi_m1_admin"));if err!=nil{t.Fatal(err)}
 defer admin.Close(context.Background())
 writer,err:=pgx.Connect(ctx,connect("fi_ingest"));if err!=nil{t.Fatal(err)}
 defer writer.Close(context.Background())
 reader,err:=pgx.Connect(ctx,connect("fi_ingest"));if err!=nil{t.Fatal(err)}
 defer reader.Close(context.Background())
 var role,db,port,dataRoot string
 if err=admin.QueryRow(ctx,"SELECT current_user,current_database(),current_setting('port'),current_setting('data_directory')").Scan(&role,&db,&port,&dataRoot);err!=nil{t.Fatal(err)}
 if role!="fi_m1_admin"||db!="fi"||port!="55418"||filepath.Clean(dataRoot)!=filepath.Join(root,"data"){t.Fatal("STOP: wrong PostgreSQL fixture")}
 var privatePresent bool
 if err=admin.QueryRow(ctx,"SELECT to_regnamespace('fi_recovery') IS NOT NULL OR to_regnamespace('fi_recovery_projection') IS NOT NULL").Scan(&privatePresent);err!=nil{t.Fatal(err)}
 if privatePresent{t.Fatal("STOP: pre-existing private schema")}
 var canonicalGenerations int64
 if err=admin.QueryRow(ctx,"SELECT count(*) FROM fi.recorded_generation").Scan(&canonicalGenerations);err!=nil{t.Fatal(err)}
 if canonicalGenerations!=0{t.Fatal("STOP: canonical SoR is not empty")}
 // This test owns these two private schemas. Cleanup is scoped exclusively
 // to this disposable test environment, never a production database.
 if _,err=admin.Exec(ctx,isolatedTypedWindowSchema,pgx.QueryExecModeSimpleProtocol);err!=nil{t.Fatal(err)}
 defer func(){
  cleanup,stop:=context.WithTimeout(context.Background(),30*time.Second);defer stop()
  if _,e:=admin.Exec(cleanup,"DROP SCHEMA IF EXISTS fi_recovery CASCADE");e!=nil{t.Errorf("ledger cleanup: %v",e)}
 }()
 for i,name:=range []string{"0001_relational.sql","0002_source_families.sql","0003_usn_relational_identity.sql","0004_security_field_name_index.sql","0005_usn_capture_binding.sql"}{
  raw,e:=os.ReadFile(filepath.Join("..","..","..","database","schema",name));if e!=nil{t.Fatal(e)}
  ddl,e:=RewritePrivateProjectionMigration(name,string(raw));if e!=nil{t.Fatal(e)}
  if _,e=admin.Exec(ctx,ddl,pgx.QueryExecModeSimpleProtocol);e!=nil{t.Fatalf("install %s: %v",name,e)}
  if i==0{
   defer func(){
    cleanup,stop:=context.WithTimeout(context.Background(),30*time.Second);defer stop()
    if _,e:=admin.Exec(cleanup,"DROP SCHEMA IF EXISTS fi_recovery_projection CASCADE");e!=nil{t.Errorf("private projection cleanup: %v",e)}
   }()
  }
 }
 source:="fi-bootstrap-promote.iss.local"
 g:=privateTypedFixture(t,source,false)
 g.Receipt.Descriptor.GenerationID="20261103T140000.000000000Z-bootstrap"
 transfer:=sha256.Sum256([]byte("bootstrap-promote/transfer/"+source))
 receipt:=sha256.Sum256([]byte("bootstrap-promote/receipt/"+source))
 g.Receipt.TransferSHA256=hex.EncodeToString(transfer[:])
 g.ReceiptSHA256=hex.EncodeToString(receipt[:])
 // Cleanup canonically promoted source in exact FK order and then its
 // journal. No other source or generation may be removed.
 defer func(){
  clean,stop:=context.WithTimeout(context.Background(),45*time.Second);defer stop()
  tx,e:=admin.Begin(clean);if e!=nil{t.Errorf("canonical cleanup start: %v",e);return}
  defer tx.Rollback(context.Background())
  for _,table:=range []string{"ntfs_collection_error","supporting_source_collection_error"}{
   q:=fmt.Sprintf(`DELETE FROM fi.%s c USING fi.source_record sr,fi.source_batch sb,fi.recorded_generation rg
WHERE c.source_record_id=sr.source_record_id AND sr.source_batch_id=sb.source_batch_id
 AND sb.recorded_generation_id=rg.recorded_generation_id AND rg.source_id=$1
 AND rg.generation_id=$2`,table)
   if _,e=tx.Exec(clean,q,source,g.Receipt.Descriptor.GenerationID);e!=nil{t.Errorf("child cleanup: %v",e);return}
  }
  for _,q:=range []string{
   `DELETE FROM fi.source_record sr USING fi.source_batch sb,fi.recorded_generation rg
WHERE sr.source_batch_id=sb.source_batch_id AND sb.recorded_generation_id=rg.recorded_generation_id
 AND rg.source_id=$1 AND rg.generation_id=$2`,
   `DELETE FROM fi.source_batch sb USING fi.recorded_generation rg
WHERE sb.recorded_generation_id=rg.recorded_generation_id AND rg.source_id=$1 AND rg.generation_id=$2`,
   `DELETE FROM fi.recorded_generation WHERE source_id=$1 AND generation_id=$2`,
  }{
   if _,e=tx.Exec(clean,q,source,g.Receipt.Descriptor.GenerationID);e!=nil{t.Errorf("canonical cleanup: %v",e);return}
  }
  if _,e=tx.Exec(clean,`DELETE FROM fi.ingest_journal WHERE source_id=$1 AND generation_id=$2`,
   source,g.Receipt.Descriptor.GenerationID);e!=nil{t.Errorf("journal cleanup: %v",e);return}
  if e=tx.Commit(clean);e!=nil{t.Errorf("cleanup COMMIT: %v",e)}
 }()
 limits:=BacklogWindowLimits{MaxRecords:3,MaxDataBytes:1<<20}
 privateRoot:=privateBacklogTestRoot(t)
 for i:=0;i<2;i++{
  if _,err=MaterializeBacklogWindow(ctx,g,limits,i,privateRoot);err!=nil{t.Fatal(err)}
  if err=RecordVerifiedBacklogArtifactWindow(ctx,writer,g,limits,i,privateRoot);err!=nil{t.Fatal(err)}
  if err=StageVerifiedBacklogSourceWindow(ctx,writer,g,limits,i,privateRoot);err!=nil{t.Fatal(err)}
  if err=StageBacklogTypedWindow(ctx,reader,writer,g,limits,i,privateRoot);err!=nil{t.Fatal(err)}
 }
 // An explicit late failure must rollback the earlier table inserts and
 // never write Accepted. Only the test database receives this constraint.
 if _,err=admin.Exec(ctx,`ALTER TABLE fi.supporting_source_collection_error
ADD CONSTRAINT fi_bootstrap_test_late_fail CHECK (false) NOT VALID`);err!=nil{t.Fatal(err)}
 deferredConstraint:=true
 defer func(){
  if deferredConstraint {
   cleanup,stop:=context.WithTimeout(context.Background(),10*time.Second);defer stop()
   if _,e:=admin.Exec(cleanup,`ALTER TABLE fi.supporting_source_collection_error
DROP CONSTRAINT IF EXISTS fi_bootstrap_test_late_fail`);e!=nil{t.Errorf("test constraint cleanup: %v",e)}
  }
 }()
 if _,err=BootstrapPromoteVerifiedBacklogToEmptySoR(ctx,reader,admin,g,limits,"fi-bootstrap-rejected");err==nil{
  t.Fatal("late field failure produced Accepted")
 }
 var leaked int64
 if err=admin.QueryRow(ctx,`SELECT
(SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1)
+(SELECT count(*) FROM fi.source_record sr JOIN fi.source_batch sb USING(source_batch_id)
 JOIN fi.recorded_generation rg USING(recorded_generation_id) WHERE rg.source_id=$1)
+(SELECT count(*) FROM fi.ingest_journal WHERE source_id=$1 AND outcome='Accepted')`,source).Scan(&leaked);err!=nil{t.Fatal(err)}
 if leaked!=0 {t.Fatalf("late failure leaked %d authoritative rows",leaked)}
 if _,err=admin.Exec(ctx,`ALTER TABLE fi.supporting_source_collection_error
DROP CONSTRAINT fi_bootstrap_test_late_fail`);err!=nil{t.Fatal(err)}
 deferredConstraint=false
 result,err:=BootstrapPromoteVerifiedBacklogToEmptySoR(ctx,reader,admin,g,limits,"fi-bootstrap-accepted")
 if err!=nil{t.Fatal(err)}
 if result.Outcome!="Accepted" || result.RecordsSeen!=6 || result.RecordsCommitted!=6 || result.RecordedGenerationID<=0{
  t.Fatalf("incorrect canonical promotion: %+v",result)
 }
 var recs,errorsNTFS,errorsSupporting,accepted int64
 if err=reader.QueryRow(ctx,`SELECT
 (SELECT count(*) FROM fi.source_record sr JOIN fi.source_batch sb USING(source_batch_id)
  WHERE sb.recorded_generation_id=$1),
 (SELECT count(*) FROM fi.ntfs_collection_error e JOIN fi.source_record sr USING(source_record_id)
  JOIN fi.source_batch sb USING(source_batch_id) WHERE sb.recorded_generation_id=$1),
 (SELECT count(*) FROM fi.supporting_source_collection_error e JOIN fi.source_record sr USING(source_record_id)
  JOIN fi.source_batch sb USING(source_batch_id) WHERE sb.recorded_generation_id=$1),
 (SELECT count(*) FROM fi.ingest_journal WHERE source_id=$2 AND outcome='Accepted')
 `,result.RecordedGenerationID,source).Scan(&recs,&errorsNTFS,&errorsSupporting,&accepted);err!=nil{t.Fatal(err)}
 if recs!=6 || errorsNTFS!=3 || errorsSupporting!=3 || accepted!=1 {
  t.Fatalf("accepted SQL mismatch records=%d ntfs=%d supporting=%d journal=%d",recs,errorsNTFS,errorsSupporting,accepted)
 }
 // A second generation cannot silently use this bootstrap-only route.
 if _,err=BootstrapPromoteVerifiedBacklogToEmptySoR(ctx,reader,admin,g,limits,"fi-bootstrap-retry");err==nil{
  t.Fatal("nonempty canonical SoR accepted bootstrap without remapping")
 }
 t.Log("PASS: 48-table SQL promotion, late rollback, one atomic Accepted, exact signed counts, nonempty-SoR rejection")
}
