//go:build freebsd && fi_backlog_typed_window_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/jackc/pgx/v5"
)

//go:embed backlog_artifact_ledger_schema.sql
var isolatedSecurityWindowSchema string

// securityWindowFixture uses valid WindowsSecurityEvent observations from FI's
// existing source contract. The last record of the second batch can be made
// invalid only at the typed-projection layer (not the envelope layer).
func securityWindowFixture(t *testing.T, source string, invalidLate bool) *PreparedGeneration {
	t.Helper()
	g:=privateTypedFixture(t,source,false)
	if invalidLate {
		g.Receipt.Descriptor.GenerationID="20261101T130002.000000000Z-security-reject"
		g.Receipt.TransferSHA256=strings.Repeat("a",64)
		g.ReceiptSHA256=strings.Repeat("b",64)
	}
	g.Receipt.DataBytes=0
	for bi:=range g.Batches {
		b:=&g.Batches[bi]
		var data []byte
		for n:=0;n<b.Manifest.RecordCount;n++ {
			num:=bi*3+n
			scopes:=[]records.WindowsSecurityMatchedScope{
				{ScopeID:"security-window",GovernedRoot:`C:\FI-Window`},
			}
			if num%2==0 {
				scopes=append(scopes,records.WindowsSecurityMatchedScope{
					ScopeID:"security-secondary",GovernedRoot:`D:\FI-Window`,
				})
			}
			fields:=[]records.WindowsSecurityEventField{
				{Name:"AccessMask",Value:"0x2"},
				{Name:"ObjectName",Value:fmt.Sprintf(`C:\FI-Window\object-%d.txt`,num)},
			}
			if num%2==1 {
				fields=append(fields,records.WindowsSecurityEventField{
					Name:"HandleId",Value:fmt.Sprintf("0x%x",num+1),
				})
			}
			event:=records.WindowsSecurityEventObservation{
				ObservedAt:"2026-11-01T13:00:00.123456789Z",
				CollectionMethod:records.WindowsSecurityCollectionMethod,
				Channel:"Security",
				Provider:"Microsoft-Windows-Security-Auditing",
				EventID:"4663",
				EventRecordID:strconv.Itoa(100000+num),
				TimeCreated:"2026-11-01T13:00:00.123456789Z",
				Computer:"fi-security-window-test.iss.local",
				AuditResult:records.WindowsSecurityAuditSuccess,
				ScopeBasis:records.WindowsSecurityScopePathMatched,
				MatchedScopes:scopes,
				Fields:fields,
				RawXML:fmt.Sprintf("<Event><EventRecordID>%d</EventRecordID></Event>",100000+num),
			}
			if invalidLate&&bi==1&&n==2{
				event.EventRecordID="invalid-event-record-id"
			}else if err:=records.ValidateWindowsSecurityEventObservation(event);err!=nil{
				t.Fatalf("invalid synthetic event %d: %v",num,err)
			}
			payload,err:=json.Marshal(event);if err!=nil{t.Fatal(err)}
			envelope:=spool.Record{
				Version:SpoolRecordVersion,RecordKind:"WindowsSecurityEvent",
				ScopeID:"security-window",
				WrittenAt:"2026-11-01T13:00:00.123456789Z",
				Payload:payload,
			}
			record,err:=json.Marshal(envelope);if err!=nil{t.Fatal(err)}
			data=append(data,record...)
			data=append(data,'\n')
		}
		path:=filepath.Join(t.TempDir(),"security.jsonl")
		if err:=os.WriteFile(path,data,0600);err!=nil{t.Fatal(err)}
		b.DataPath=path
		b.Manifest.DataBytes=int64(len(data))
		h:=sha256.Sum256(data)
		b.Manifest.DataSHA256=hex.EncodeToString(h[:])
		manifest,err:=json.Marshal(b.Manifest);if err!=nil{t.Fatal(err)}
		b.ManifestRawBytes=manifest
		b.ManifestBytes=len(manifest)
		mh:=sha256.Sum256(manifest)
		b.ManifestSHA256=hex.EncodeToString(mh[:])
		g.Receipt.DataBytes+=uint64(len(data))
	}
	return g
}

func TestBacklogSecurityWindowIsolatedDurableAtomicity(t *testing.T){
	if os.Getenv("FI_M1_ALLOW_ISOLATED_WRITES")!="1"{
		t.Skip("isolated PostgreSQL Security window acceptance disabled")
	}
	root:=filepath.Join(os.Getenv("HOME"),"fi-m1-postgres-20261012")
	if os.Getenv("FI_M1_TEST_POSTGRES_ROOT")!=root{t.Fatal("STOP: unexpected fixture path")}
	version,err:=os.ReadFile(filepath.Join(root,"data","PG_VERSION"))
	if err!=nil||string(version)!="18\n"{t.Fatal("STOP: PostgreSQL 18 fixture missing")}
	ctx,cancel:=context.WithTimeout(context.Background(),3*time.Minute);defer cancel()
	connect:=func(user string)string {
		return fmt.Sprintf("host=%s port=55418 user=%s dbname=fi sslmode=disable connect_timeout=3",
			filepath.Join(root,"socket"),user)
	}
	admin,err:=pgx.Connect(ctx,connect("fi_m1_admin"));if err!=nil{t.Fatal(err)}
	t.Cleanup(func(){_ = admin.Close(context.Background())})
	writer,err:=pgx.Connect(ctx,connect("fi_ingest"));if err!=nil{t.Fatal(err)}
	t.Cleanup(func(){_ = writer.Close(context.Background())})
	reader,err:=pgx.Connect(ctx,connect("fi_ingest"));if err!=nil{t.Fatal(err)}
	t.Cleanup(func(){_ = reader.Close(context.Background())})

	for _,c:=range []struct{conn *pgx.Conn;role string}{
		{admin,"fi_m1_admin"},{writer,"fi_ingest"},{reader,"fi_ingest"},
	}{
		var role,db,port,version string
		if err:=c.conn.QueryRow(ctx,`SELECT current_user,current_database(),
current_setting('port'),current_setting('server_version_num')`).
			Scan(&role,&db,&port,&version);err!=nil{t.Fatal(err)}
		if role!=c.role||db!="fi"||port!="55418"||!strings.HasPrefix(version,"18"){
			t.Fatalf("STOP: wrong fixture identity %s/%s port=%s version=%s",role,db,port,version)
		}
	}
	var dataDir string
	if err:=admin.QueryRow(ctx,"SELECT current_setting('data_directory')").Scan(&dataDir);err!=nil{t.Fatal(err)}
	if filepath.Clean(dataDir)!=filepath.Join(root,"data"){t.Fatalf("STOP: wrong data directory %s",dataDir)}
	var existing bool
	if err:=admin.QueryRow(ctx,`SELECT
to_regnamespace('fi_recovery') IS NOT NULL OR
to_regnamespace('fi_recovery_projection') IS NOT NULL`).Scan(&existing);err!=nil{t.Fatal(err)}
	if existing{t.Fatal("STOP: existing recovery schema - cannot overwrite")}
	if _,err:=admin.Exec(ctx,isolatedSecurityWindowSchema,pgx.QueryExecModeSimpleProtocol);err!=nil{t.Fatal(err)}
	t.Cleanup(func(){
		c,done:=context.WithTimeout(context.Background(),30*time.Second);defer done()
		if _,err:=admin.Exec(c,"DROP SCHEMA fi_recovery CASCADE");err!=nil{t.Errorf("private ledger cleanup: %v",err)}
	})
	for i,name:=range []string{
		"0001_relational.sql","0002_source_families.sql",
		"0003_usn_relational_identity.sql","0004_security_field_name_index.sql",
		"0005_usn_capture_binding.sql",
	}{
		raw,err:=os.ReadFile(filepath.Join("..","..","..","database","schema",name))
		if err!=nil{t.Fatal(err)}
		ddl,err:=RewritePrivateProjectionMigration(name,string(raw))
		if err!=nil{t.Fatal(err)}
		if _,err:=admin.Exec(ctx,ddl,pgx.QueryExecModeSimpleProtocol);err!=nil{
			t.Fatalf("shadow schema migration %s: %v",name,err)
		}
		if i==0{t.Cleanup(func(){
			c,done:=context.WithTimeout(context.Background(),30*time.Second);defer done()
			if _,err:=admin.Exec(c,"DROP SCHEMA fi_recovery_projection CASCADE");err!=nil{
				t.Errorf("shadow cleanup: %v",err)
			}
		})}
	}

	source:="fi-security-backlog-isolated.iss.local"
	g:=securityWindowFixture(t,source,false)
	stageRoot:=privateBacklogTestRoot(t)
	limits:=BacklogWindowLimits{MaxRecords:3,MaxDataBytes:1<<20}
	for i:=0;i<2;i++{
		if _,err:=MaterializeBacklogWindow(ctx,g,limits,i,stageRoot);err!=nil{t.Fatal(err)}
		if err:=RecordVerifiedBacklogArtifactWindow(ctx,writer,g,limits,i,stageRoot);err!=nil{t.Fatal(err)}
		if err:=StageVerifiedBacklogSourceWindow(ctx,writer,g,limits,i,stageRoot);err!=nil{t.Fatal(err)}
	}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,g,limits,1,stageRoot);err==nil{
		t.Fatal("Security window 1 accepted without window 0")
	}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,g,limits,0,stageRoot);err!=nil{t.Fatal(err)}
	if err:=writer.Close(ctx);err!=nil{t.Fatal(err)}
	writer,err=pgx.Connect(ctx,connect("fi_ingest"));if err!=nil{t.Fatal(err)}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,g,limits,0,stageRoot);err!=nil{
		t.Fatalf("Security window 0 restart replay not idempotent: %v",err)
	}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,g,limits,1,stageRoot);err!=nil{t.Fatal(err)}
	var eventCount,scopeCount,fieldCount,sourceRows,completed,authoritative int64
	if err:=writer.QueryRow(ctx,`
SELECT
 (SELECT count(*) FROM fi_recovery_projection.windows_security_event e
    JOIN fi_recovery_projection.source_record sr USING(source_record_id)
    JOIN fi_recovery_projection.source_batch sb USING(source_batch_id)
    JOIN fi_recovery_projection.recorded_generation rg USING(recorded_generation_id)
    WHERE rg.source_id=$1),
 (SELECT count(*) FROM fi_recovery_projection.windows_security_event_scope es
    JOIN fi_recovery_projection.source_record sr USING(source_record_id)
    JOIN fi_recovery_projection.source_batch sb USING(source_batch_id)
    JOIN fi_recovery_projection.recorded_generation rg USING(recorded_generation_id)
    WHERE rg.source_id=$1),
 (SELECT count(*) FROM fi_recovery_projection.windows_security_event_field ef
    JOIN fi_recovery_projection.source_record sr USING(source_record_id)
    JOIN fi_recovery_projection.source_batch sb USING(source_batch_id)
    JOIN fi_recovery_projection.recorded_generation rg USING(recorded_generation_id)
    WHERE rg.source_id=$1),
 (SELECT count(*) FROM fi_recovery_projection.source_record sr
    JOIN fi_recovery_projection.source_batch sb USING(source_batch_id)
    JOIN fi_recovery_projection.recorded_generation rg USING(recorded_generation_id)
    WHERE rg.source_id=$1),
 (SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=decode($2,'hex')),
 (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1)
`,source,g.ReceiptSHA256).Scan(&eventCount,&scopeCount,&fieldCount,&sourceRows,&completed,&authoritative);err!=nil{t.Fatal(err)}
	if eventCount!=6||scopeCount!=9||fieldCount!=15||sourceRows!=6||completed!=2||authoritative!=0{
		t.Fatalf("STOP: events=%d scopes=%d fields=%d records=%d typed windows=%d canonical=%d",
			eventCount,scopeCount,fieldCount,sourceRows,completed,authoritative)
	}
	// The first source batch's Security event/child COPY succeeds; a late
	// invalid event in the second batch then rejects the SAME typed transaction.
	// No shadow generation, source row, child or completion marker may escape.
	badSource:="fi-security-backlog-rejected.iss.local"
	bad:=securityWindowFixture(t,badSource,true)
	badRoot:=privateBacklogTestRoot(t)
	badLimits:=BacklogWindowLimits{MaxRecords:6,MaxDataBytes:1<<20}
	if _,err:=MaterializeBacklogWindow(ctx,bad,badLimits,0,badRoot);err!=nil{t.Fatal(err)}
	if err:=RecordVerifiedBacklogArtifactWindow(ctx,writer,bad,badLimits,0,badRoot);err!=nil{t.Fatal(err)}
	if err:=StageVerifiedBacklogSourceWindow(ctx,writer,bad,badLimits,0,badRoot);err!=nil{t.Fatal(err)}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,bad,badLimits,0,badRoot);err==nil{
		t.Fatal("invalid late Security event was accepted after prior batch COPY")
	}
	var leakedGen,leakedRows,leakedEvents,leakedMarkers int64
	if err:=writer.QueryRow(ctx,`
SELECT
 (SELECT count(*) FROM fi_recovery_projection.recorded_generation WHERE source_id=$1),
 (SELECT count(*) FROM fi_recovery_projection.source_record sr
    JOIN fi_recovery_projection.source_batch sb USING(source_batch_id)
    JOIN fi_recovery_projection.recorded_generation rg USING(recorded_generation_id)
    WHERE rg.source_id=$1),
 (SELECT count(*) FROM fi_recovery_projection.windows_security_event e
    JOIN fi_recovery_projection.source_record sr USING(source_record_id)
    JOIN fi_recovery_projection.source_batch sb USING(source_batch_id)
    JOIN fi_recovery_projection.recorded_generation rg USING(recorded_generation_id)
    WHERE rg.source_id=$1),
 (SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=decode($2,'hex'))
`,badSource,bad.ReceiptSHA256).Scan(&leakedGen,&leakedRows,&leakedEvents,&leakedMarkers);err!=nil{t.Fatal(err)}
	if leakedGen!=0||leakedRows!=0||leakedEvents!=0||leakedMarkers!=0{
		t.Fatalf("STOP: failed Security typed transaction leaked generation=%d records=%d events=%d marker=%d",
			leakedGen,leakedRows,leakedEvents,leakedMarkers)
	}
	t.Log("PASS: Security events/scopes/fields, 2 windows and reconnect, late COPY rollback, canonical SoR untouched")
}
