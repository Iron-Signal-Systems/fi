//go:build fi_bootstrap_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
 "context"
 "crypto/sha256"
 _ "embed"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
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
var bootstrapCILedgerSchema string

// CI uses a NEW disposable PostgreSQL 18 container with a fresh database fi.
// This never points at fi-dev's long-lived fi-m1 fixture or any signed backlog.
// It proves correctness only; real-data throughput acceptance remains separate.
func bootstrapCIFixture(t *testing.T, source string, badLate bool) *PreparedGeneration {
	t.Helper()
	g := backlogWindowFixture([]int{3, 3}, 1)
	g.Receipt.Version = "fi-fixture-recorded-receipt/1"
	d := &g.Receipt.Descriptor
	d.Version = "fi-fixture-generation/1"
	d.SourceID = source
	d.GenerationID = "20261101T130000.000000000Z-typed-test"
	d.CanonicalVersion = "fi-test-canonical"
	d.DataEncoding = "fi-test-encoding"
	d.ArtifactCount = 4
	d.SourceBytes = 4096
	d.CanonicalBytes = 4096
	d.CanonicalSHA256 = strings.Repeat("1", 64)
	d.EncodedDataBytes = 2048
	d.EncodedDataSHA256 = strings.Repeat("2", 64)
	g.Receipt.MetadataBytes = 256
	g.Receipt.MetadataSHA256 = strings.Repeat("3", 64)
	g.Receipt.TransferBytes = 4096
	g.Receipt.TransferSHA256 = strings.Repeat("4", 64)
	g.ReceiptSHA256 = strings.Repeat("5", 64)
	if badLate {
		d.GenerationID = "20261101T130001.000000000Z-typed-bad"
		g.Receipt.TransferSHA256 = strings.Repeat("6", 64)
		g.ReceiptSHA256 = strings.Repeat("7", 64)
	}
	g.ReceiptBytes = 256
	g.Receipt.DataBytes = 0
	for bi := range g.Batches {
		b := &g.Batches[bi]
		b.DataArtifactName = "batch-" + b.BatchID + ".jsonl"
		b.ManifestArtifactName = "batch-" + b.BatchID + ".manifest.json"
		b.Manifest.DataFile = b.DataArtifactName
		b.Manifest.Version = "fi-fixture-spool-manifest"
		b.Manifest.CreatedAt = "2026-11-01T12:59:00Z"
		b.Manifest.CompletedAt = "2026-11-01T13:00:00Z"
		b.Manifest.Collector.ExecutablePath = "C:\\FI\\synthetic.exe"
		b.Manifest.Collector.ExecutableSHA256 = strings.Repeat("8", 64)
		var data []byte
		for n := 0; n < b.Manifest.RecordCount; n++ {
			kind := "NTFSCollectionError"
			var payload any = ntfsCollectionErrorPayload{
				PathDisplay:          "C:\\FI\\test",
				PathUTF16LEBase64URL: base64.RawURLEncoding.EncodeToString([]byte{'C', 0, ':', 0, '\\', 0, 'F', 0, 'I', 0}),
				Error:                "synthetic",
			}
			if bi == 1 {
				kind = "SupportingSourceCollectionError"
				payload = supportingSourceCollectionErrorPayload{Source: "synthetic", Error: "synthetic"}
			}
			if badLate && bi == 0 && n == 2 {
				payload = ntfsCollectionErrorPayload{PathDisplay: "C:\\bad", PathUTF16LEBase64URL: "invalid%%%", Error: "late projection failure"}
			}
			rawPayload, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			env := spool.Record{
				Version: SpoolRecordVersion, RecordKind: kind,
				ScopeID:   fmt.Sprintf("test-scope-%d", bi),
				WrittenAt: "2026-11-01T13:00:00.123456789Z", Payload: rawPayload,
			}
			recordBytes, err := json.Marshal(env)
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, recordBytes...)
			data = append(data, '\n')
		}
		file := filepath.Join(t.TempDir(), "data.jsonl")
		if err := os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
		b.DataPath = file
		b.Manifest.DataBytes = int64(len(data))
		hash := sha256.Sum256(data)
		b.Manifest.DataSHA256 = hex.EncodeToString(hash[:])
		manifestBytes, err := json.Marshal(b.Manifest)
		if err != nil {
			t.Fatal(err)
		}
		b.ManifestRawBytes = manifestBytes
		b.ManifestBytes = len(manifestBytes)
		mh := sha256.Sum256(manifestBytes)
		b.ManifestSHA256 = hex.EncodeToString(mh[:])
		g.Receipt.DataBytes += uint64(len(data))
	}
	return g
}

func TestBacklogBootstrapPromoteFreshIsolatedPostgres(t *testing.T) {
 if os.Getenv("GITHUB_ACTIONS")!="true" ||
  os.Getenv("FI_BOOTSTRAP_CI_ALLOW_ISOLATED_WRITES")!="1" {
  t.Skip("disposable PostgreSQL 18 CI service is required")
 }
 ctx,stop:=context.WithTimeout(context.Background(),5*time.Minute)
 defer stop()
 adminDSN:=os.Getenv("FI_BOOTSTRAP_CI_PG_ADMIN_DSN")
 ingestDSN:=os.Getenv("FI_BOOTSTRAP_CI_PG_INGEST_DSN")
 if adminDSN=="" || ingestDSN=="" {t.Fatal("STOP: explicit isolated CI DSNs required")}
 admin,err:=pgx.Connect(ctx,adminDSN)
 if err!=nil {t.Fatal(err)}
 defer admin.Close(context.Background())
 var role,db,port string
 var version int
 var fiPresent bool
 err=admin.QueryRow(ctx,`SELECT current_user,current_database(),current_setting('port'),
current_setting('server_version_num')::integer,
to_regnamespace('fi') IS NOT NULL`).Scan(&role,&db,&port,&version,&fiPresent)
 if err!=nil {t.Fatal(err)}
 if role!="fi_m1_admin" || db!="fi" || port!="5432" || version<180000 || fiPresent {
  t.Fatalf("STOP: not the fresh PostgreSQL 18 CI fixture: %q/%q/%q/%d fi_present=%v",
   role,db,port,version,fiPresent)
 }
 // CI's unique container has no persistent data and is destroyed after test.
 for _,sql:=range []string{
  `CREATE ROLE fi_owner NOLOGIN`,
  `CREATE ROLE fi_ingest LOGIN PASSWORD 'isolated-only-test'`,
 }{
  if _,err=admin.Exec(ctx,sql);err!=nil{t.Fatal(err)}
 }
 for _,name:=range []string{"0001_relational.sql","0002_source_families.sql",
 "0003_usn_relational_identity.sql","0004_security_field_name_index.sql",
 "0005_usn_capture_binding.sql"}{
  raw,readErr:=os.ReadFile(filepath.Join("..","..","..","database","schema",name))
  if readErr!=nil {t.Fatal(readErr)}
  if _,err=admin.Exec(ctx,string(raw),pgx.QueryExecModeSimpleProtocol);err!=nil {
   t.Fatalf("canonical DDL %s: %v",name,err)
  }
 }
 writer,err:=pgx.Connect(ctx,ingestDSN)
 if err!=nil{t.Fatal(err)}
 defer writer.Close(context.Background())
 reader,err:=pgx.Connect(ctx,ingestDSN)
 if err!=nil{t.Fatal(err)}
 defer reader.Close(context.Background())
 var who,where,dbPort string
 if err=writer.QueryRow(ctx,"SELECT current_user,current_database(),current_setting('port')").Scan(&who,&where,&dbPort);err!=nil{t.Fatal(err)}
 if who!="fi_ingest"||where!="fi"||dbPort!="5432" {t.Fatal("STOP: wrong test ingester role/database")}
 // This test owns these two private schemas. Cleanup is scoped exclusively
 // to this disposable test environment, never a production database.
 if _,err=admin.Exec(ctx,bootstrapCILedgerSchema,pgx.QueryExecModeSimpleProtocol);err!=nil{t.Fatal(err)}
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
 g:=bootstrapCIFixture(t,source,false)
 g.Receipt.Descriptor.GenerationID="20261103T140000.000000000Z-bootstrap"
 transfer:=sha256.Sum256([]byte("bootstrap-promote/transfer/"+source))
 receipt:=sha256.Sum256([]byte("bootstrap-promote/receipt/"+source))
 g.Receipt.TransferSHA256=hex.EncodeToString(transfer[:])
 g.ReceiptSHA256=hex.EncodeToString(receipt[:])
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
 // The same signed generation is idempotent. No additional journal rows.
 replay,err:=BootstrapPromoteVerifiedBacklogToEmptySoR(ctx,reader,admin,g,limits,"fi-bootstrap-retry")
 if err!=nil || replay.Outcome!="AlreadyAccepted" || replay.RecordedGenerationID!=result.RecordedGenerationID {
  t.Fatalf("exact accepted generation not idempotent: %+v %v",replay,err)
 }
 var journalCount int64
 if err=reader.QueryRow(ctx,`SELECT count(*) FROM fi.ingest_journal
WHERE source_id=$1 AND outcome='Accepted'`,source).Scan(&journalCount);err!=nil{t.Fatal(err)}
 if journalCount!=1 {t.Fatal("retry created another Accepted journal")}
 t.Log("PASS: 48-table SQL promotion, late rollback, one atomic Accepted, exact signed counts, idempotent retry")
}
