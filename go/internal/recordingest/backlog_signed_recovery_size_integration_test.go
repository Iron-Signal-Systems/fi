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
 "runtime"
 "strconv"
 "syscall"
 "testing"
 "time"

 "github.com/jackc/pgx/v5"
)

// This measures recovery and canonical publication of one newly signed,
// trusted 32K/64K generation; no real backlog data is opened or changed.
// All writes are limited to the disposable PostgreSQL 18 M1 database.
func TestSignedBacklogRecoveryAndPublicationSize(t *testing.T) {
 if os.Getenv("FI_M1_ALLOW_ISOLATED_WRITES")!="1" {t.Skip("isolated PostgreSQL writes disabled")}
 root:=filepath.Join(os.Getenv("HOME"),"fi-m1-postgres-20261012")
 if os.Getenv("FI_M1_TEST_POSTGRES_ROOT")!=root {t.Fatal("STOP: isolated PostgreSQL root mismatch")}
 version,err:=os.ReadFile(filepath.Join(root,"data","PG_VERSION"))
 if err!=nil||string(version)!="18\n" {t.Fatal("STOP: expected PostgreSQL 18 fixture")}
 count:=32768
 if v:=os.Getenv("FI_MULTIBATCH_RECORDS");v!="" {
  count,err=strconv.Atoi(v)
  if err!=nil||(count!=32768&&count!=65536){t.Fatal("FI_MULTIBATCH_RECORDS must be 32768 or 65536")}
 }
 for key,want:=range map[string]string{
  "FI_MULTIBATCH_MIX":"observed",
  "FI_MULTIBATCH_BATCH_RECORDS":"8192",
  "FI_MULTIBATCH_FILE_PROFILE":"F3",
  "FI_MULTIBATCH_SECURITY_PROFILE":"P3",
 }{
  if v:=os.Getenv(key);v!=""&&v!=want {t.Fatalf("%s must be %s",key,want)}
 }
 ctx,cancel:=context.WithTimeout(context.Background(),45*time.Minute);defer cancel()
 ctx,err=withFixedFileBulkProfile(ctx,"F3");if err!=nil{t.Fatal(err)}
 ctx,err=withFixedSecurityBulkProfile(ctx,"P3");if err!=nil{t.Fatal(err)}
 connect:=func(user string)string{return fmt.Sprintf("host=%s port=55418 user=%s dbname=fi sslmode=disable connect_timeout=3",filepath.Join(root,"socket"),user)}
 admin,err:=pgx.Connect(ctx,connect("fi_m1_admin"));if err!=nil{t.Fatal(err)}
 t.Cleanup(func(){_ = admin.Close(context.Background())})
 writer,state,err:=OpenPostgreSQL(ctx,connect("fi_ingest"));if err!=nil{t.Fatal(err)}
 t.Cleanup(func(){_ = writer.Close(context.Background())})
 reader,err:=pgx.Connect(ctx,connect("fi_ingest"));if err!=nil{t.Fatal(err)}
 t.Cleanup(func(){_ = reader.Close(context.Background())})
 for _,item:=range []struct{conn *pgx.Conn; role string}{{admin,"fi_m1_admin"},{writer,"fi_ingest"},{reader,"fi_ingest"}}{
  m1VerifyIsolatedPostgreSQL(t,ctx,item.conn,root,item.role)
 }
 if state.RelationalTables!=49 {t.Fatalf("STOP: canonical relational tables=%d",state.RelationalTables)}
 var generations,journal,volumes int64
 var private,index bool
 err=admin.QueryRow(ctx,`SELECT
 (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1),
 (SELECT count(*) FROM fi.ingest_journal WHERE source_id=$1),
 (SELECT count(*) FROM fi.ntfs_volume WHERE source_id=$1),
 (to_regnamespace('fi_recovery') IS NOT NULL OR to_regnamespace('fi_recovery_projection') IS NOT NULL),
 (to_regclass('fi.fi_multibatch_parent_cleanup_idx') IS NOT NULL)`,multiBatchSource).
 Scan(&generations,&journal,&volumes,&private,&index)
 if err!=nil||generations!=0||journal!=0||volumes!=0||private||index{
  t.Fatalf("STOP: isolated fixture not clean: generations=%d journal=%d volumes=%d private=%v index=%v err=%v",generations,journal,volumes,private,index,err)
 }

 // Create only previously absent test-owned private schemas.
 if _,err:=admin.Exec(ctx,isolatedTypedWindowSchema,pgx.QueryExecModeSimpleProtocol);err!=nil{t.Fatal(err)}
 t.Cleanup(func(){
  c,stop:=context.WithTimeout(context.Background(),2*time.Minute);defer stop()
  if _,err:=admin.Exec(c,"DROP SCHEMA fi_recovery CASCADE");err!=nil{t.Errorf("test-owned ledger cleanup: %v",err)}
 })
 for i,name:=range []string{"0001_relational.sql","0002_source_families.sql","0003_usn_relational_identity.sql","0004_security_field_name_index.sql","0005_usn_capture_binding.sql"}{
  raw,err:=os.ReadFile(filepath.Join("..","..","..","database","schema",name));if err!=nil{t.Fatal(err)}
  ddl,err:=RewritePrivateProjectionMigration(name,string(raw));if err!=nil{t.Fatal(err)}
  if _,err:=admin.Exec(ctx,ddl,pgx.QueryExecModeSimpleProtocol);err!=nil{t.Fatalf("install private %s: %v",name,err)}
  if i==0 {t.Cleanup(func(){
   c,stop:=context.WithTimeout(context.Background(),2*time.Minute);defer stop()
   if _,err:=admin.Exec(c,"DROP SCHEMA fi_recovery_projection CASCADE");err!=nil{t.Errorf("test-owned projection cleanup: %v",err)}
  })}
 }

 fixture:=t.TempDir()
 for _,p:=range []string{"custody","recorded","ready",filepath.Join("recorded","sources",multiBatchSource),filepath.Join(multiBatchSource,"frozen"),filepath.Join(multiBatchSource,"sealed")}{
  if err:=os.MkdirAll(filepath.Join(fixture,p),0700);err!=nil{t.Fatal(err)}
 }
 buildStarted:=time.Now()
 signed,batchCount,sourceBytes,securityCount,fileCount:=writeMultiBatchSignedGeneration(t,fixture,"observed",count,8192)
 buildTime:=time.Since(buildStarted)
 if batchCount!=count/8192 {t.Fatalf("unexpected signed batch count: %d",batchCount)}
 attemptID:="multibatch-"+signed.GenerationID
 // The established source/generation-scoped cleanup is registered before
 // any canonical writes and runs before private schema removal.
 t.Cleanup(func(){cleanupMultiBatchReplay(t,admin,signed.GenerationID,attemptID)})
 prepared,err:=loadRecordedGenerationWithTrust(GenerationLoadConfig{
  CustodyRoot:filepath.Join(fixture,"custody"),RecordedRoot:filepath.Join(fixture,"recorded"),
  SourceNamespaces:true,SourceID:multiBatchSource,
  MaxCanonicalBytes:multiBatchMaxGenerationBytes,MaxEncodedBytes:multiBatchMaxGenerationBytes,
  MaxManifestBytes:1<<20,
 },signed.GenerationID,func(source string)(generationTrustBundle,error){
  if source!=multiBatchSource{return generationTrustBundle{},fmt.Errorf("untrusted fixture source %q",source)}
  return signed.Trust,nil
 })
 if err!=nil{t.Fatal(err)}
 defer prepared.Close()
 if prepared.Receipt.RecordCount!=uint64(count)||len(prepared.Batches)!=batchCount{t.Fatal("signed record/batch mismatch")}
 limits:=BacklogWindowLimits{MaxRecords:8192,MaxDataBytes:32<<20}
 desc,err:=DescribeBacklogWindows(prepared,limits);if err!=nil{t.Fatal(err)}
 if len(desc)!=batchCount{t.Fatalf("expected %d whole-batch windows; got %d",batchCount,len(desc))}
 privateRoot:=privateBacklogTestRoot(t)
 var walStart,walPrivateEnd string
 if err:=admin.QueryRow(ctx,"SELECT pg_current_wal_lsn()::text").Scan(&walStart);err!=nil{t.Fatal(err)}

 var artifactTime,ledgerTime,sourceTime,typedTime time.Duration
 privateStarted:=time.Now()
 for i:=range desc{
  start:=time.Now()
  if _,err:=MaterializeBacklogWindow(ctx,prepared,limits,i,privateRoot);err!=nil{t.Fatalf("artifact window %d: %v",i,err)}
  artifactTime+=time.Since(start)
  start=time.Now()
  if err:=RecordVerifiedBacklogArtifactWindow(ctx,writer,prepared,limits,i,privateRoot);err!=nil{t.Fatalf("artifact ledger window %d: %v",i,err)}
  ledgerTime+=time.Since(start)
  start=time.Now()
  if err:=StageVerifiedBacklogSourceWindow(ctx,writer,prepared,limits,i,privateRoot);err!=nil{t.Fatalf("source window %d: %v",i,err)}
  sourceTime+=time.Since(start)
  start=time.Now()
  if err:=StageBacklogTypedWindow(ctx,reader,writer,prepared,limits,i,privateRoot);err!=nil{t.Fatalf("typed window %d: %v",i,err)}
  typedTime+=time.Since(start)
  t.Logf("FI RECOVERY WINDOW index=%d done=%d/%d artifact=%s ledger=%s source=%s typed=%s",
   i,i+1,len(desc),artifactTime.Round(time.Millisecond),ledgerTime.Round(time.Millisecond),sourceTime.Round(time.Millisecond),typedTime.Round(time.Millisecond))
 }
 privateTime:=time.Since(privateStarted)
 verifyStarted:=time.Now()
 verified,err:=VerifyCompleteBacklogTypedGeneration(ctx,reader,prepared,limits)
 verifyTime:=time.Since(verifyStarted)
 if err!=nil{t.Fatalf("complete private generation: %v",err)}
 if verified.Records!=uint64(count)||verified.Windows!=batchCount||verified.DataBytes!=prepared.Receipt.DataBytes{
  t.Fatalf("wrong completed private generation: %+v",verified)
 }
 if err:=admin.QueryRow(ctx,"SELECT pg_current_wal_lsn()::text").Scan(&walPrivateEnd);err!=nil{t.Fatal(err)}
 var privateWAL int64
 if err:=admin.QueryRow(ctx,"SELECT pg_wal_lsn_diff($1::pg_lsn,$2::pg_lsn)::bigint",walPrivateEnd,walStart).Scan(&privateWAL);err!=nil{t.Fatal(err)}
 t.Logf("FI RECOVERY PRIVATE records=%d batches=%d windows=%d source_bytes=%d build=%s artifact=%s ledger=%s source=%s typed=%s private_total=%s verify=%s wal_bytes=%d",
  count,batchCount,len(desc),sourceBytes,buildTime.Round(time.Millisecond),artifactTime.Round(time.Millisecond),
  ledgerTime.Round(time.Millisecond),sourceTime.Round(time.Millisecond),typedTime.Round(time.Millisecond),
  privateTime.Round(time.Millisecond),verifyTime.Round(time.Millisecond),privateWAL)

 var before,after runtime.MemStats
 runtime.ReadMemStats(&before)
 publishStarted:=time.Now()
 result,err:=PublishVerifiedBacklogWithAuthoritativeIngest(ctx,reader,writer,prepared,limits,attemptID)
 publishTime:=time.Since(publishStarted)
 runtime.ReadMemStats(&after)
 if err!=nil{t.Fatalf("authoritative publish: %v",err)}
 if result.Outcome!="Accepted"||result.RecordsCommitted!=int64(count)||result.RecordsSeen!=int64(count){
  t.Fatalf("canonical outcome mismatch: %+v",result)
 }
 // Use explicit joins. The source_record table must not self-join.
 var sources,events,fields,files,accepted int64
 err=admin.QueryRow(ctx,`SELECT
 (SELECT count(*) FROM fi.source_record sr JOIN fi.source_batch sb ON sb.source_batch_id=sr.source_batch_id JOIN fi.recorded_generation rg ON rg.recorded_generation_id=sb.recorded_generation_id WHERE rg.source_id=$1 AND rg.generation_id=$2),
 (SELECT count(*) FROM fi.windows_security_event e JOIN fi.source_record sr ON sr.source_record_id=e.source_record_id JOIN fi.source_batch sb ON sb.source_batch_id=sr.source_batch_id JOIN fi.recorded_generation rg ON rg.recorded_generation_id=sb.recorded_generation_id WHERE rg.source_id=$1 AND rg.generation_id=$2),
 (SELECT count(*) FROM fi.windows_security_event_field f JOIN fi.source_record sr ON sr.source_record_id=f.source_record_id JOIN fi.source_batch sb ON sb.source_batch_id=sr.source_batch_id JOIN fi.recorded_generation rg ON rg.recorded_generation_id=sb.recorded_generation_id WHERE rg.source_id=$1 AND rg.generation_id=$2),
 (SELECT count(*) FROM fi.file_observation f JOIN fi.source_record sr ON sr.source_record_id=f.source_record_id JOIN fi.source_batch sb ON sb.source_batch_id=sr.source_batch_id JOIN fi.recorded_generation rg ON rg.recorded_generation_id=sb.recorded_generation_id WHERE rg.source_id=$1 AND rg.generation_id=$2),
 (SELECT count(*) FROM fi.ingest_journal WHERE source_id=$1 AND generation_id=$2 AND outcome='Accepted')`,multiBatchSource,signed.GenerationID).
 Scan(&sources,&events,&fields,&files,&accepted)
 if err!=nil{t.Fatal(err)}
 if sources!=int64(count)||events!=int64(securityCount)||fields!=int64(securityCount*securityReplayFields)||files!=int64(fileCount)||accepted!=1{
  t.Fatalf("canonical rows mismatch source=%d events=%d fields=%d file=%d accepted=%d",sources,events,fields,files,accepted)
 }
 replay,err:=PublishVerifiedBacklogWithAuthoritativeIngest(ctx,reader,writer,prepared,limits,attemptID)
 if err!=nil||replay.Outcome!="AlreadyAccepted"{t.Fatalf("canonical replay failed: result=%+v err=%v",replay,err)}
 var journalEvents int64
 if err:=admin.QueryRow(ctx,"SELECT count(*) FROM fi.ingest_journal WHERE attempt_id=$1",attemptID).Scan(&journalEvents);err!=nil{t.Fatal(err)}
 if journalEvents!=2{t.Fatalf("canonical journal duplicate: %d",journalEvents)}
 var publicWAL int64
 if err:=admin.QueryRow(ctx,"SELECT pg_wal_lsn_diff(pg_current_wal_lsn(),$1::pg_lsn)::bigint",walPrivateEnd).Scan(&publicWAL);err!=nil{t.Fatal(err)}
 var usage syscall.Rusage
 if err:=syscall.Getrusage(syscall.RUSAGE_SELF,&usage);err!=nil{t.Fatal(err)}
 t.Logf("FI RECOVERY PUBLISHED records=%d security=%d fields=%d file=%d private=%s verify=%s publish=%s publish_rate=%.1f_source_records_per_second wal_private_bytes=%d wal_canonical_bytes=%d heap_before_mib=%.1f heap_after_mib=%.1f go_maxrss_kib=%d journal_events=%d",
  count,securityCount,fields,fileCount,privateTime.Round(time.Millisecond),verifyTime.Round(time.Millisecond),
  publishTime.Round(time.Millisecond),float64(count)/publishTime.Seconds(),privateWAL,publicWAL,
  float64(before.HeapAlloc)/(1<<20),float64(after.HeapAlloc)/(1<<20),usage.Maxrss,journalEvents)
}
