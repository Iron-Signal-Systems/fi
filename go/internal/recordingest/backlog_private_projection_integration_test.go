//go:build freebsd && fi_backlog_private_projection_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
    "context"
    "encoding/base64"
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

// This test never creates a production schema. It runs only in the existing,
// explicit PostgreSQL 18 fixture and drops ONLY its test-owned shadow schema.
func TestBacklogPrivateProjectionSchemaAndTypedProjector(t *testing.T){
    if os.Getenv("FI_M1_ALLOW_ISOLATED_WRITES")!="1"{
        t.Skip("isolated PostgreSQL shadow projection test disabled")
    }
    root:=filepath.Join(os.Getenv("HOME"),"fi-m1-postgres-20261012")
    if os.Getenv("FI_M1_TEST_POSTGRES_ROOT")!=root{t.Fatal("STOP: isolated PostgreSQL root mismatch")}
    version,err:=os.ReadFile(filepath.Join(root,"data","PG_VERSION"))
    if err!=nil||string(version)!="18\n"{t.Fatal("STOP: isolated PostgreSQL 18 marker missing")}
    ctx,cancel:=context.WithTimeout(context.Background(),3*time.Minute)
    defer cancel()
    dsn:=func(user string)string{
        return fmt.Sprintf("host=%s port=55418 user=%s dbname=fi sslmode=disable connect_timeout=3",
            filepath.Join(root,"socket"),user)
    }
    admin,err:=pgx.Connect(ctx,dsn("fi_m1_admin"));if err!=nil{t.Fatal(err)}
    t.Cleanup(func(){_ = admin.Close(context.Background())})
    runtime,err:=pgx.Connect(ctx,dsn("fi_ingest"));if err!=nil{t.Fatal(err)}
    t.Cleanup(func(){_ = runtime.Close(context.Background())})
    for _,item:=range []struct{conn *pgx.Conn;user string}{
        {admin,"fi_m1_admin"},{runtime,"fi_ingest"},
    }{
        var user,db,port,version string
        if err:=item.conn.QueryRow(ctx,
            "SELECT current_user,current_database(),current_setting('port'),current_setting('server_version_num')").
            Scan(&user,&db,&port,&version);err!=nil{t.Fatal(err)}
        if user!=item.user||db!="fi"||port!="55418"||!strings.HasPrefix(version,"18"){
            t.Fatalf("STOP: unexpected PostgreSQL fixture %s/%s port=%s version=%s",user,db,port,version)
        }
    }
    var dataDir string
    if err:=admin.QueryRow(ctx,"SELECT current_setting('data_directory')").Scan(&dataDir);err!=nil{t.Fatal(err)}
    if filepath.Clean(dataDir)!=filepath.Join(root,"data"){t.Fatalf("STOP: wrong data directory %s",dataDir)}
    var exists bool
    if err:=admin.QueryRow(ctx,
        "SELECT to_regnamespace('fi_recovery_projection') IS NOT NULL").Scan(&exists);err!=nil{t.Fatal(err)}
    if exists{t.Fatal("STOP: shadow projection schema already exists; refuse to modify it")}

    // Test-owned schema is created by the first real FI migration. Record
    // cleanup immediately after that succeeds, so any later error cleans it.
    names:=[]string{"0001_relational.sql","0002_source_families.sql",
        "0003_usn_relational_identity.sql","0004_security_field_name_index.sql",
        "0005_usn_capture_binding.sql"}
    for i,name:=range names{
        content,err:=os.ReadFile(filepath.Join("..","..","..","database","schema",name))
        if err!=nil{t.Fatal(err)}
        ddl,err:=RewritePrivateProjectionMigration(name,string(content))
        if err!=nil{t.Fatal(err)}
        if _,err:=admin.Exec(ctx,ddl,pgx.QueryExecModeSimpleProtocol);err!=nil{
            t.Fatalf("private migration %s: %v",name,err)
        }
        if i==0 {
            t.Cleanup(func(){
                cleanupCtx,cleanupCancel:=context.WithTimeout(context.Background(),30*time.Second)
                defer cleanupCancel()
                if _,err:=admin.Exec(cleanupCtx,
                    "DROP SCHEMA fi_recovery_projection CASCADE");err!=nil{
                    t.Errorf("isolated shadow schema cleanup: %v",err)
                }
            })
        }
    }
    var canonicalTables,shadowTables,unisolatedFKs int64
    if err:=admin.QueryRow(ctx,`
SELECT
 (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='fi' AND c.relkind='r'),
 (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
   WHERE n.nspname='fi_recovery_projection' AND c.relkind='r'),
 (SELECT count(*) FROM pg_constraint fk
   JOIN pg_class child ON child.oid=fk.conrelid
   JOIN pg_namespace cn ON cn.oid=child.relnamespace
   JOIN pg_class parent ON parent.oid=fk.confrelid
   JOIN pg_namespace pn ON pn.oid=parent.relnamespace
   WHERE cn.nspname='fi_recovery_projection' AND fk.contype='f'
     AND pn.nspname<>'fi_recovery_projection')
`).Scan(&canonicalTables,&shadowTables,&unisolatedFKs);err!=nil{t.Fatal(err)}
    if canonicalTables!=49||shadowTables!=canonicalTables||unisolatedFKs!=0{
        t.Fatalf("STOP: relational shadow tables canonical=%d shadow=%d cross-schema FKs=%d",
            canonicalTables,shadowTables,unisolatedFKs)
    }
    var canUpdate,canDelete,canTruncate bool
    if err:=runtime.QueryRow(ctx,`
SELECT has_table_privilege(current_user,'fi_recovery_projection.source_record','UPDATE'),
       has_table_privilege(current_user,'fi_recovery_projection.source_record','DELETE'),
       has_table_privilege(current_user,'fi_recovery_projection.source_record','TRUNCATE')
`).Scan(&canUpdate,&canDelete,&canTruncate);err!=nil{t.Fatal(err)}
    if canUpdate||canDelete||canTruncate{t.Fatal("STOP: ingest runtime received destructive shadow privileges")}

    source:="fi-shadow-projection-acceptance.iss.local"
    var originalCount int64
    if err:=admin.QueryRow(ctx,"SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1",source).
       Scan(&originalCount);err!=nil{t.Fatal(err)}
    if originalCount!=0{t.Fatal("STOP: test source already present in authoritative SoR")}

    tx,err:=runtime.Begin(ctx);if err!=nil{t.Fatal(err)}
    defer tx.Rollback(context.Background())
    shadow:=privateProjectionTx{Tx:tx}
    var generationID int64
    err=shadow.QueryRow(ctx,`
INSERT INTO fi.recorded_generation (
 receipt_version,descriptor_version,source_id,generation_id,
 canonical_version,data_encoding,artifact_count,source_bytes,
 canonical_bytes,canonical_sha256,encoded_data_bytes,encoded_data_sha256,
 metadata_bytes,metadata_sha256,transfer_bytes,transfer_sha256,
 batch_count,data_bytes,record_count,receipt_bytes,receipt_sha256,ingest_version
) VALUES (
 'synthetic-test','synthetic-test',$1,'synthetic-shadow-generation',
 'synthetic-test','synthetic-test',2,100,100,decode(repeat('a',64),'hex'),
 100,decode(repeat('b',64),'hex'),10,decode(repeat('c',64),'hex'),
 110,decode(repeat('d',64),'hex'),1,100,1,100,decode(repeat('e',64),'hex'),$2
) RETURNING recorded_generation_id
`,source,IngestVersion).Scan(&generationID)
    if err!=nil{t.Fatal(err)}

    var batchID int64
    err=shadow.QueryRow(ctx,`
INSERT INTO fi.source_batch (
 recorded_generation_id,manifest_artifact_name,data_artifact_name,
 manifest_version,batch_id,target_batch_size,record_count,data_bytes,
 data_sha256,data_file,collector_executable_path,collector_executable_sha256,
 created_at,completed_at,manifest_bytes,manifest_sha256
) VALUES (
 $1,'batch-shadow.manifest.json','batch-shadow.jsonl',
 'fi-spool-manifest/0.1','shadow',2,1,100,decode(repeat('f',64),'hex'),
 'batch-shadow.jsonl','C:\\fi\\synthetic.exe',decode(repeat('1',64),'hex'),
 '2026-11-01T12:00:00Z','2026-11-01T12:00:01Z',100,decode(repeat('2',64),'hex')
) RETURNING source_batch_id
`,generationID).Scan(&batchID)
    if err!=nil{t.Fatal(err)}

    pathUTF16:=base64.RawURLEncoding.EncodeToString([]byte{'C',0,':',0,'\\',0,'t',0})
    payload,err:=json.Marshal(ntfsCollectionErrorPayload{
        PathDisplay:"C:\\t",PathUTF16LEBase64URL:pathUTF16,Error:"synthetic source error",
    })
    if err!=nil{t.Fatal(err)}
    env:=spool.Record{
        Version:SpoolRecordVersion,RecordKind:"NTFSCollectionError",
        ScopeID:"fi-shadow-fixture",WrittenAt:"2026-11-01T12:00:00.123456789Z",
        Payload:payload,
    }
    raw,err:=json.Marshal(env);if err!=nil{t.Fatal(err)}
    record,err:=PrepareSourceRecord(append(raw,'\n'));if err!=nil{t.Fatal(err)}
    var sourceRecordID int64
    err=shadow.QueryRow(ctx,`
INSERT INTO fi.source_record (
 source_batch_id,record_ordinal,version,record_kind,scope_id,
 written_at,record_bytes,record_sha256,ingest_version
) VALUES ($1,1,$2,$3,$4,$5,$6,decode($7,'hex'),$8)
RETURNING source_record_id
`,batchID,record.Record.Version,record.Record.RecordKind,record.Record.ScopeID,
        record.WrittenAtUTC,record.RecordBytes,record.RecordSHA256,IngestVersion).Scan(&sourceRecordID)
    if err!=nil{t.Fatal(err)}

    if err:=ProjectSourceRecord(ctx,shadow,source,sourceRecordID,record);err!=nil{t.Fatal(err)}
    if err:=tx.Commit(ctx);err!=nil{t.Fatal(err)}

    var typed,authoritative,authoritativeTyped int64
    if err:=runtime.QueryRow(ctx,`
SELECT
 (SELECT count(*) FROM fi_recovery_projection.ntfs_collection_error),
 (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1),
 (SELECT count(*) FROM fi.ntfs_collection_error e
    JOIN fi.source_record sr ON sr.source_record_id=e.source_record_id
    JOIN fi.source_batch sb ON sb.source_batch_id=sr.source_batch_id
    JOIN fi.recorded_generation rg ON rg.recorded_generation_id=sb.recorded_generation_id
   WHERE rg.source_id=$1)
`,source).Scan(&typed,&authoritative,&authoritativeTyped);err!=nil{t.Fatal(err)}
    if typed!=1||authoritative!=0||authoritativeTyped!=0{
        t.Fatalf("STOP: shadow typed=%d canonical generations=%d typed=%d",typed,authoritative,authoritativeTyped)
    }

    // Prove source and projection writes cannot survive a late rejection:
    // a valid source-record insert followed by an invalid typed payload
    // must both roll back within the original pending window transaction.
    rollbackTx,err:=runtime.Begin(ctx);if err!=nil{t.Fatal(err)}
    rollbackShadow:=privateProjectionTx{Tx:rollbackTx}
    var badID int64
    err=rollbackShadow.QueryRow(ctx,`
INSERT INTO fi.source_record(
 source_batch_id,record_ordinal,version,record_kind,scope_id,
 written_at,record_bytes,record_sha256,ingest_version)
VALUES($1,2,$2,$3,$4,$5,$6,decode($7,'hex'),$8)
RETURNING source_record_id
`,batchID,record.Record.Version,record.Record.RecordKind,record.Record.ScopeID,
        record.WrittenAtUTC,record.RecordBytes,record.RecordSHA256,IngestVersion).Scan(&badID)
    if err!=nil{t.Fatal(err)}
    invalid:=record
    invalid.Record.Payload=json.RawMessage(`{"path_display":"C:\\\\bad","path_utf16le_base64url":"invalid%%%","error":"failure"}`)
    if err:=ProjectSourceRecord(ctx,rollbackShadow,source,badID,invalid);err==nil{
        t.Fatal("invalid typed payload accepted")
    }
    if err:=rollbackTx.Rollback(ctx);err!=nil{t.Fatal(err)}
    var remaining int64
    if err:=runtime.QueryRow(ctx,
       "SELECT count(*) FROM fi_recovery_projection.source_record").Scan(&remaining);err!=nil{t.Fatal(err)}
    if remaining!=1{t.Fatalf("STOP: failed projection leaked pending source records: %d",remaining)}
    t.Log("PASS: 49-table private schema, isolated foreign keys, existing typed projector, late rollback, canonical SoR unchanged")
}
