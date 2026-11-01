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
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/jackc/pgx/v5"
)

// securityCoverageWindowFixture keeps the same original signed generation
// across four original source batches. A private typed window comprises two
// whole source batches; coverage COPY must flush across their boundary.
func securityCoverageWindowFixture(t *testing.T, source string, invalidLate bool) *PreparedGeneration {
    t.Helper()
    base := privateTypedFixture(t,source,false)
    g := backlogWindowFixture([]int{2,2,2,2},1)
    g.Receipt = base.Receipt
    g.ReceiptBytes = base.ReceiptBytes
    g.Receipt.Descriptor.SourceID = source
    g.Receipt.Descriptor.GenerationID = "20261101T133000.000000000Z-coverage"
    g.Receipt.Descriptor.ArtifactCount = 8
    g.Receipt.BatchCount = 4
    g.Receipt.RecordCount = 8
    g.Receipt.DataBytes = 0
    g.ReceiptSHA256 = strings.Repeat("e",64)
    g.Receipt.TransferSHA256 = strings.Repeat("c",64)
    if invalidLate {
        g.Receipt.Descriptor.GenerationID = "20261101T133100.000000000Z-coverage-rejected"
        g.ReceiptSHA256 = strings.Repeat("f",64)
        g.Receipt.TransferSHA256 = strings.Repeat("d",64)
    }
    const observed = "2026-11-01T13:30:00.123456789Z"
    policy := records.WindowsSecurityAuditPolicyObservation{
        SubcategoryGUID: "{11111111-1111-1111-1111-111111111111}",
        AuditingInformation: "Success and Failure",
        SuccessEnabled: true,
        FailureEnabled: true,
    }
    coverage := records.WindowsSecurityCoverageObservation{
        ObservedAt: observed,
        CollectionMethod: records.WindowsSecurityCollectionMethod,
        SecurityLogReadable: false,
        FileSystemPolicy: policy,
        HandleManipulationPolicy: policy,
        DetailedFileSharePolicy: policy,
        AuditPolicyChangePolicy: policy,
        Roots: []records.WindowsSecurityRootAuditCoverage{
            {ScopeID:"root-a", GovernedRoot:`C:\FI-Coverage`, SACLState:"Present",
                RecommendedChangeAuditPresent:true,RecommendedReadAuditPresent:true},
            {ScopeID:"root-b", GovernedRoot:`D:\FI-Coverage`, SACLState:"Error",ReasonCode:"NotKnown"},
        },
        Status:records.WindowsSecurityCoveragePartial,
    }
    if err:=records.ValidateWindowsSecurityCoverageObservation(coverage);err!=nil{t.Fatal(err)}
    for bi:=range g.Batches {
        batch:=&g.Batches[bi]
        batch.DataArtifactName="batch-"+batch.BatchID+".jsonl"
        batch.ManifestArtifactName="batch-"+batch.BatchID+".manifest.json"
        batch.Manifest.DataFile=batch.DataArtifactName
        batch.Manifest.Version="fi-fixture-spool-manifest"
        batch.Manifest.CreatedAt="2026-11-01T13:29:00Z"
        batch.Manifest.CompletedAt="2026-11-01T13:30:00Z"
        batch.Manifest.Collector.ExecutablePath=`C:\FI\synthetic.exe`
        batch.Manifest.Collector.ExecutableSHA256=strings.Repeat("8",64)
        var data []byte
        for n:=0;n<batch.Manifest.RecordCount;n++ {
            kind:="WindowsSecurityCoverage"
            var payload any=coverage
            // Normally each two-batch window has three consecutive
            // coverage records, followed by an event which flushes them.
            if (bi==1||bi==3)&&n==1 || (invalidLate&&bi==0&&n==1) {
                kind="WindowsSecurityEvent"
                event:=records.WindowsSecurityEventObservation{
                    ObservedAt:observed,
                    CollectionMethod:records.WindowsSecurityCollectionMethod,
                    Channel:"Security",
                    Provider:"Microsoft-Windows-Security-Auditing",
                    EventID:"4663",
                    EventRecordID:fmt.Sprintf("%d",200000+bi*2+n),
                    TimeCreated:observed,
                    Computer:"fi-coverage-test.iss.local",
                    AuditResult:records.WindowsSecurityAuditSuccess,
                    ScopeBasis:records.WindowsSecurityScopePathMatched,
                    MatchedScopes:[]records.WindowsSecurityMatchedScope{
                        {ScopeID:"root-a",GovernedRoot:`C:\FI-Coverage`},
                    },
                    Fields:[]records.WindowsSecurityEventField{
                        {Name:"AccessMask",Value:"0x2"},
                        {Name:"ObjectName",Value:`C:\FI-Coverage\test.txt`},
                    },
                    RawXML:fmt.Sprintf("<Event><RecordID>%d</RecordID></Event>",bi*2+n),
                }
                if err:=records.ValidateWindowsSecurityEventObservation(event);err!=nil{t.Fatal(err)}
                payload=event
            }
            // In the rejection fixture, the last record of source batch
            // 1 fails typed validation, after batch 0's coverage COPY
            // was forced to flush by its valid WindowsSecurityEvent.
            if invalidLate&&bi==1&&n==1 {
                kind="WindowsSecurityCoverage"
                bad:=coverage
                bad.Status=records.WindowsSecurityCoverageStatus("Invalid")
                payload=bad
            }
            rawPayload,err:=json.Marshal(payload)
            if err!=nil{t.Fatal(err)}
            envelope:=spool.Record{
                Version:SpoolRecordVersion,RecordKind:kind,
                ScopeID:"root-a",WrittenAt:observed,Payload:rawPayload,
            }
            raw,err:=json.Marshal(envelope)
            if err!=nil{t.Fatal(err)}
            data=append(data,raw...)
            data=append(data,'\n')
        }
        path:=filepath.Join(t.TempDir(),"coverage.jsonl")
        if err:=os.WriteFile(path,data,0600);err!=nil{t.Fatal(err)}
        batch.DataPath=path
        batch.Manifest.DataBytes=int64(len(data))
        dh:=sha256.Sum256(data)
        batch.Manifest.DataSHA256=hex.EncodeToString(dh[:])
        manifest,err:=json.Marshal(batch.Manifest)
        if err!=nil{t.Fatal(err)}
        batch.ManifestRawBytes=manifest
        batch.ManifestBytes=len(manifest)
        mh:=sha256.Sum256(manifest)
        batch.ManifestSHA256=hex.EncodeToString(mh[:])
        g.Receipt.DataBytes+=uint64(len(data))
    }
    return g
}

// exerciseBacklogSecurityCoverageWindows runs inside the existing strictly
// verified isolated PostgreSQL 18 test. It owns only two new test sources;
// its enclosing test owns the temporary recovery and shadow schemas.
func exerciseBacklogSecurityCoverageWindows(t *testing.T,ctx context.Context,reader,writer *pgx.Conn) {
    t.Helper()
    g:=securityCoverageWindowFixture(t,"fi-coverage-window-acceptance.iss.local",false)
    privateRoot:=privateBacklogTestRoot(t)
    limits:=BacklogWindowLimits{MaxRecords:4,MaxDataBytes:1<<20}
    for i:=0;i<2;i++ {
        if _,err:=MaterializeBacklogWindow(ctx,g,limits,i,privateRoot);err!=nil{t.Fatal(err)}
        if err:=RecordVerifiedBacklogArtifactWindow(ctx,writer,g,limits,i,privateRoot);err!=nil{t.Fatal(err)}
        if err:=StageVerifiedBacklogSourceWindow(ctx,writer,g,limits,i,privateRoot);err!=nil{t.Fatal(err)}
    }
    if err:=StageBacklogTypedWindow(ctx,reader,writer,g,limits,1,privateRoot);err==nil{
        t.Fatal("coverage window 1 admitted without typed window 0")
    }
    if err:=StageBacklogTypedWindow(ctx,reader,writer,g,limits,0,privateRoot);err!=nil{t.Fatal(err)}
    // Simulate disconnect/restart by reopening a separate ingest session.
    resumed,err:=pgx.ConnectConfig(ctx,writer.Config().Copy())
    if err!=nil{t.Fatal(err)}
    defer resumed.Close(context.Background())
    if err:=StageBacklogTypedWindow(ctx,reader,resumed,g,limits,0,privateRoot);err!=nil{
        t.Fatalf("coverage window zero replay: %v",err)
    }
    if err:=StageBacklogTypedWindow(ctx,reader,resumed,g,limits,1,privateRoot);err!=nil{t.Fatal(err)}

    var coverageRows,policyRows,rootRows,eventRows,scopeRows,fieldRows,markerRows,sourceRows,canonical int64
    err=resumed.QueryRow(ctx,`
SELECT
 (SELECT count(*) FROM fi_recovery_projection.windows_security_coverage c
 JOIN fi_recovery_projection.source_record sr USING (source_record_id)
 JOIN fi_recovery_projection.source_batch sb USING (source_batch_id)
 JOIN fi_recovery_projection.recorded_generation rg USING (recorded_generation_id)
 WHERE rg.source_id=$1),
 (SELECT count(*) FROM fi_recovery_projection.windows_security_audit_policy p
 JOIN fi_recovery_projection.source_record sr USING (source_record_id)
 JOIN fi_recovery_projection.source_batch sb USING (source_batch_id)
 JOIN fi_recovery_projection.recorded_generation rg USING (recorded_generation_id)
 WHERE rg.source_id=$1),
 (SELECT count(*) FROM fi_recovery_projection.windows_security_root_coverage r
 JOIN fi_recovery_projection.source_record sr USING (source_record_id)
 JOIN fi_recovery_projection.source_batch sb USING (source_batch_id)
 JOIN fi_recovery_projection.recorded_generation rg USING (recorded_generation_id)
 WHERE rg.source_id=$1),
 (SELECT count(*) FROM fi_recovery_projection.windows_security_event e
 JOIN fi_recovery_projection.source_record sr USING (source_record_id)
 JOIN fi_recovery_projection.source_batch sb USING (source_batch_id)
 JOIN fi_recovery_projection.recorded_generation rg USING (recorded_generation_id)
 WHERE rg.source_id=$1),
 (SELECT count(*) FROM fi_recovery_projection.windows_security_event_scope sc
 JOIN fi_recovery_projection.source_record sr USING (source_record_id)
 JOIN fi_recovery_projection.source_batch sb USING (source_batch_id)
 JOIN fi_recovery_projection.recorded_generation rg USING (recorded_generation_id)
 WHERE rg.source_id=$1),
 (SELECT count(*) FROM fi_recovery_projection.windows_security_event_field f
 JOIN fi_recovery_projection.source_record sr USING (source_record_id)
 JOIN fi_recovery_projection.source_batch sb USING (source_batch_id)
 JOIN fi_recovery_projection.recorded_generation rg USING (recorded_generation_id)
 WHERE rg.source_id=$1),
 (SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=decode($2,'hex')),
 (SELECT count(*) FROM fi_recovery_projection.source_record sr
 JOIN fi_recovery_projection.source_batch sb USING (source_batch_id)
 JOIN fi_recovery_projection.recorded_generation rg USING (recorded_generation_id)
 WHERE rg.source_id=$1),
 (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1)
`,g.Receipt.Descriptor.SourceID,g.ReceiptSHA256).Scan(
    &coverageRows,&policyRows,&rootRows,&eventRows,&scopeRows,&fieldRows,&markerRows,&sourceRows,&canonical)
    if err!=nil{t.Fatal(err)}
    if coverageRows!=6||policyRows!=24||rootRows!=12||eventRows!=2||scopeRows!=2||
        fieldRows!=4||markerRows!=2||sourceRows!=8||canonical!=0 {
        t.Fatalf("STOP: coverage=%d policies=%d roots=%d events=%d scopes=%d fields=%d markers=%d source=%d canonical=%d",
            coverageRows,policyRows,rootRows,eventRows,scopeRows,fieldRows,markerRows,sourceRows,canonical)
    }

    // Late invalid coverage follows successful Security coverage COPY and
    // event COPY in the first batch of one typed transaction.
    bad:=securityCoverageWindowFixture(t,"fi-coverage-window-rejected.iss.local",true)
    badRoot:=privateBacklogTestRoot(t)
    if _,err:=MaterializeBacklogWindow(ctx,bad,limits,0,badRoot);err!=nil{t.Fatal(err)}
    if err:=RecordVerifiedBacklogArtifactWindow(ctx,writer,bad,limits,0,badRoot);err!=nil{t.Fatal(err)}
    if err:=StageVerifiedBacklogSourceWindow(ctx,writer,bad,limits,0,badRoot);err!=nil{t.Fatal(err)}
    if err:=StageBacklogTypedWindow(ctx,reader,writer,bad,limits,0,badRoot);err==nil{
        t.Fatal("late invalid coverage record committed")
    }
    var leakedSource,leakedCoverage,leakedTyped int64
    err=writer.QueryRow(ctx,`
SELECT
 (SELECT count(*) FROM fi_recovery_projection.source_record sr
  JOIN fi_recovery_projection.source_batch sb USING(source_batch_id)
  JOIN fi_recovery_projection.recorded_generation rg USING(recorded_generation_id)
  WHERE rg.source_id=$1),
 (SELECT count(*) FROM fi_recovery_projection.recorded_generation WHERE source_id=$1),
 (SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=decode($2,'hex'))
`,bad.Receipt.Descriptor.SourceID,bad.ReceiptSHA256).Scan(&leakedSource,&leakedCoverage,&leakedTyped)
    if err!=nil{t.Fatal(err)}
    if leakedSource!=0||leakedCoverage!=0||leakedTyped!=0{
        t.Fatalf("STOP: invalid coverage left private typed state source=%d gen=%d marker=%d",
            leakedSource,leakedCoverage,leakedTyped)
    }
    t.Log("PASS: coverage buffering across batches, 4 audit policies and 2 roots per coverage, restart, late COPY rollback, zero authoritative SoR rows")
}
