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
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/jackc/pgx/v5"
)

const backlogUSNScope = "usn-recovery-scope"
const backlogUSNObservedAt = "2026-11-01T14:00:00.123456789Z"

func backlogUSNBoundary(sourceBound bool, expectedObjects int) usnReadBoundaryPayload {
	b:=usnReadBoundaryPayload{
		ObservedAt:backlogUSNObservedAt,
		CollectionMethod:records.WindowsUSNCollectionMethod,
		VolumeIdentity:records.VolumeIdentity{
			MethodVersion:ntfs.IdentityMethodVersion,
			VolumeGUID:`\\?\Volume{12345678-1234-1234-1234-123456789abc}\`,
			VolumeSerial:"123456789",
		},
		JournalID:"7",StartUSN:"100",NextUSN:"200",
		SourceRecordCount:expectedObjects,
		SourceDistinctObjectCount:expectedObjects,
		SelectedRecordCount:expectedObjects,
		SelectedObjectCount:expectedObjects,
		ScopeUnresolvedObjectCount:expectedObjects,
		ReObservationOperationID:"fi-recovery-reobserve",
		USNReadOperationID:"fi-recovery-legacy-read",
	}
	if sourceBound {
		b.SourceBatchSHA256=strings.Repeat("a",64)
		b.CorrelationSHA256=strings.Repeat("b",64)
		root:=records.NTFSObjectIdentity{
			MethodVersion:ntfs.IdentityMethodVersion,
			FileReferenceNumber:"5",SequenceNumber:"1",
		}
		b.RootIdentity=&root
		b.USNReadOperationID=""
	}
	return b
}

func backlogUSNObject(frn int,sourceBound bool,invalidChange bool) usnObjectObservationPayload {
	file:=records.NTFSObjectIdentity{
		MethodVersion:ntfs.IdentityMethodVersion,
		FileReferenceNumber:fmt.Sprint(frn),SequenceNumber:"1",
	}
	parent:=records.NTFSObjectIdentity{
		MethodVersion:ntfs.IdentityMethodVersion,
		FileReferenceNumber:"5",SequenceNumber:"1",
	}
	change:=records.USNChangeObservation{
		MajorVersion:"2",MinorVersion:"0",FileIdentity:file,ParentIdentity:parent,
		USN:fmt.Sprint(frn*10),Timestamp:backlogUSNObservedAt,
		ReasonRaw:"2",ReasonNames:[]string{"CLOSE","FILE_CREATE"},
		SourceInfoRaw:"0",SecurityID:"0",FileAttributesRaw:"32",
		FileNameUTF16LEBase64URL:"ZgA",
	}
	if invalidChange {
		change.FileIdentity.FileReferenceNumber="999999"
	}
	v:=usnObjectObservationPayload{
		FileIdentity:file,ScopeBasis:"ScopeUnresolvedIncluded",
		Status:"Unavailable",ReasonCode:"TEST_UNAVAILABLE",
		Changes:[]records.USNChangeObservation{change},
	}
	if sourceBound {v.SourceBatchSHA256=strings.Repeat("a",64)}
	return v
}

func backlogUSNGap() records.USNContinuityGapObservation {
	return records.USNContinuityGapObservation{
		ObservedAt:backlogUSNObservedAt,
		CollectionMethod:records.WindowsUSNCollectionMethod,
		ScopeID:backlogUSNScope,GovernedRoot:`C:\FI-USN`,
		ReasonCode:"TEST_JOURNAL_GAP",
		CheckpointJournalID:"7",CheckpointNextUSN:"100",
		CurrentJournalID:"8",CurrentFirstUSN:"200",
		CurrentLowestValidUSN:"200",CurrentNextUSN:"300",
		CoverageState:records.USNContinuityGapCoverageIncomplete,
		ReconciliationAction:records.USNContinuityGapReconcileBaselineAndCatchUp,
	}
}

// The first committed window contains a legacy boundary/object and a
// continuity gap. The second contains an M6.1 source-bound boundary/object,
// plus a legacy object that must resolve the older legacy boundary in SQL.
// "late-invalid" fails after earlier valid USN changes and reason COPY.
// "incomplete" has a source-bound capture count that cannot close.
func backlogUSNFixture(t *testing.T,source,scenario string)*PreparedGeneration{
	t.Helper()
	g:=privateTypedFixture(t,source,false)
	hash:=sha256.Sum256([]byte(source))
	g.Receipt.Descriptor.GenerationID="20261101T140000.000000000Z-"+hex.EncodeToString(hash[:8])
	g.Receipt.TransferSHA256=hex.EncodeToString(backlogUSNSHA256String(source+"/transfer"))
	g.ReceiptSHA256=hex.EncodeToString(backlogUSNSHA256String(source+"/receipt"))
	g.Receipt.DataBytes=0
	for bi:=range g.Batches{
		b:=&g.Batches[bi]
		var data []byte
		for n:=0;n<b.Manifest.RecordCount;n++{
			var kind string
			var payload any
			if bi==0{
				switch n{
				case 0:kind="USNReadBoundary";payload=backlogUSNBoundary(false,1)
				case 1:kind="USNObjectObservation";payload=backlogUSNObject(1000,false,false)
				case 2:
					if scenario=="split" || scenario=="split-overflow" || scenario=="split-missing" {
						kind="USNReadBoundary"
						payload=backlogUSNBoundary(true,1)
					}else{
						kind="USNContinuityGap";payload=backlogUSNGap()
					}
				}
			}else{
				switch n{
				case 0:
					if scenario=="split" || scenario=="split-overflow" || scenario=="split-missing" {
						kind="USNObjectObservation"
						payload=backlogUSNObject(1001,scenario!="split-missing",false)
					}else{
						kind="USNReadBoundary"
						expected:=1
						if scenario=="incomplete" {expected=2}
						payload=backlogUSNBoundary(true,expected)
					}
				case 1:
					kind="USNObjectObservation"
					payload=backlogUSNObject(1001,scenario!="split" && scenario!="split-missing",false)
				case 2:
					kind="USNObjectObservation"
					payload=backlogUSNObject(1002,false,scenario=="late-invalid")
				}
			}
			encodedPayload,err:=json.Marshal(payload);if err!=nil{t.Fatal(err)}
			env:=spool.Record{
				Version:SpoolRecordVersion,RecordKind:kind,
				ScopeID:backlogUSNScope,WrittenAt:backlogUSNObservedAt,
				Payload:encodedPayload,
			}
			encoded,err:=json.Marshal(env);if err!=nil{t.Fatal(err)}
			data=append(data,encoded...);data=append(data,'\n')
		}
		path:=filepath.Join(t.TempDir(),"usn.jsonl")
		if err:=os.WriteFile(path,data,0600);err!=nil{t.Fatal(err)}
		b.DataPath=path
		b.Manifest.DataBytes=int64(len(data))
		batchDigest:=sha256.Sum256(data)
		b.Manifest.DataSHA256=hex.EncodeToString(batchDigest[:])
		manifestRaw,err:=json.Marshal(b.Manifest);if err!=nil{t.Fatal(err)}
		b.ManifestRawBytes=manifestRaw
		b.ManifestBytes=len(manifestRaw)
		manifestDigest:=sha256.Sum256(manifestRaw)
		b.ManifestSHA256=hex.EncodeToString(manifestDigest[:])
		g.Receipt.DataBytes+=uint64(len(data))
	}
	return g
}

func backlogUSNSHA256String(value string) []byte {
	sum:=sha256.Sum256([]byte(value))
	return sum[:]
}

// Called inside the existing isolated PostgreSQL 18 typed acceptance after
// fi_recovery and fi_recovery_projection have been freshly installed.
func exerciseBacklogUSNWindows(t *testing.T,ctx context.Context,reader,writer *pgx.Conn){
	t.Helper()
	source:="fi-usn-window-accepted.iss.local"
	g:=backlogUSNFixture(t,source,"valid")
	root:=privateBacklogTestRoot(t)
	limits:=BacklogWindowLimits{MaxRecords:3,MaxDataBytes:1<<20}
	for i:=0;i<2;i++{
		if _,err:=MaterializeBacklogWindow(ctx,g,limits,i,root);err!=nil{t.Fatal(err)}
		if err:=RecordVerifiedBacklogArtifactWindow(ctx,writer,g,limits,i,root);err!=nil{t.Fatal(err)}
		if err:=StageVerifiedBacklogSourceWindow(ctx,writer,g,limits,i,root);err!=nil{t.Fatal(err)}
	}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,g,limits,1,root);err==nil{
		t.Fatal("USN second window committed ahead of original boundary window")
	}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,g,limits,0,root);err!=nil{t.Fatal(err)}
	resumed,err:=pgx.ConnectConfig(ctx,writer.Config().Copy())
	if err!=nil{t.Fatal(err)}
	defer resumed.Close(context.Background())
	if err:=StageBacklogTypedWindow(ctx,reader,resumed,g,limits,0,root);err!=nil{
		t.Fatalf("USN first typed window not resumable: %v",err)
	}
	if err:=StageBacklogTypedWindow(ctx,reader,resumed,g,limits,1,root);err!=nil{t.Fatal(err)}
	var boundaries,objects,changes,reasons,gaps,markers,canonical,crossWindowLegacy,boundCapture int64
	err=resumed.QueryRow(ctx,`
SELECT
 (SELECT count(*) FROM fi_recovery_projection.usn_read_boundary),
 (SELECT count(*) FROM fi_recovery_projection.usn_object_observation),
 (SELECT count(*) FROM fi_recovery_projection.usn_object_change),
 (SELECT count(*) FROM fi_recovery_projection.usn_object_change_reason),
 (SELECT count(*) FROM fi_recovery_projection.usn_continuity_gap),
 (SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=decode($1,'hex')),
 (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$2),
 (SELECT count(*) FROM fi_recovery_projection.usn_object_observation o
  JOIN fi_recovery_projection.source_record sr ON sr.source_record_id=o.source_record_id
  JOIN fi_recovery_projection.source_batch sb ON sb.source_batch_id=sr.source_batch_id
  JOIN fi_recovery_projection.usn_read_boundary b ON b.source_record_id=o.usn_read_boundary_source_record_id
  JOIN fi_recovery_projection.source_record br ON br.source_record_id=b.source_record_id
  JOIN fi_recovery_projection.source_batch bb ON bb.source_batch_id=br.source_batch_id
  WHERE sb.batch_id=$3 AND bb.batch_id=$4 AND o.source_batch_sha256 IS NULL),
 (SELECT count(*) FROM fi_recovery_projection.usn_object_observation o
  JOIN fi_recovery_projection.usn_read_boundary b ON b.source_record_id=o.usn_read_boundary_source_record_id
  WHERE o.source_batch_sha256=decode(repeat('a',64),'hex')
    AND b.source_batch_sha256=o.source_batch_sha256)
`,g.ReceiptSHA256,source,g.Batches[1].BatchID,g.Batches[0].BatchID).
		Scan(&boundaries,&objects,&changes,&reasons,&gaps,&markers,&canonical,&crossWindowLegacy,&boundCapture)
	if err!=nil{t.Fatal(err)}
	if boundaries!=2||objects!=3||changes!=3||reasons!=6||gaps!=1||
		markers!=2||canonical!=0||crossWindowLegacy!=1||boundCapture!=1{
		t.Fatalf("STOP: USN boundary=%d objects=%d changes=%d reasons=%d gaps=%d markers=%d canonical=%d legacyCrossWindow=%d M61Capture=%d",
			boundaries,objects,changes,reasons,gaps,markers,canonical,crossWindowLegacy,boundCapture)
	}
	// A late invalid USN change, after the prior source batch has already
	// been projected, rolls back the ENTIRE pending typed transaction.
	bad:=backlogUSNFixture(t,"fi-usn-window-late-reject.iss.local","late-invalid")
	badRoot:=privateBacklogTestRoot(t)
	whole:=BacklogWindowLimits{MaxRecords:6,MaxDataBytes:1<<20}
	if _,err:=MaterializeBacklogWindow(ctx,bad,whole,0,badRoot);err!=nil{t.Fatal(err)}
	if err:=RecordVerifiedBacklogArtifactWindow(ctx,writer,bad,whole,0,badRoot);err!=nil{t.Fatal(err)}
	if err:=StageVerifiedBacklogSourceWindow(ctx,writer,bad,whole,0,badRoot);err!=nil{t.Fatal(err)}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,bad,whole,0,badRoot);err==nil{
		t.Fatal("invalid late USN file-identity change was committed")
	}
	var leakedGen,leakedMarker int64
	err=writer.QueryRow(ctx,`
SELECT (SELECT count(*) FROM fi_recovery_projection.recorded_generation WHERE source_id=$1),
       (SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=decode($2,'hex'))
`,bad.Receipt.Descriptor.SourceID,bad.ReceiptSHA256).Scan(&leakedGen,&leakedMarker)
	if err!=nil{t.Fatal(err)}
	if leakedGen!=0||leakedMarker!=0{t.Fatalf("STOP: late USN failure leaked generation=%d marker=%d",leakedGen,leakedMarker)}

	// M6.1 completeness may not be split or silently inferred from SQL
	// presence. A boundary requiring two observations with only one present
	// must reject its window, even though all input hashes match.
	incomplete:=backlogUSNFixture(t,"fi-usn-capture-incomplete.iss.local","incomplete")
	incompleteRoot:=privateBacklogTestRoot(t)
	for i:=0;i<2;i++{
		if _,err:=MaterializeBacklogWindow(ctx,incomplete,limits,i,incompleteRoot);err!=nil{t.Fatal(err)}
		if err:=RecordVerifiedBacklogArtifactWindow(ctx,writer,incomplete,limits,i,incompleteRoot);err!=nil{t.Fatal(err)}
		if err:=StageVerifiedBacklogSourceWindow(ctx,writer,incomplete,limits,i,incompleteRoot);err!=nil{t.Fatal(err)}
	}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,incomplete,limits,0,incompleteRoot);err!=nil{t.Fatal(err)}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,incomplete,limits,1,incompleteRoot);err==nil||
		!strings.Contains(err.Error(),"capture completeness"){
		t.Fatalf("incomplete M6.1 capture was not rejected at completion boundary: %v",err)
	}
	var incompleteMarkers int64
	if err:=writer.QueryRow(ctx,`
SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=decode($1,'hex')
`,incomplete.ReceiptSHA256).Scan(&incompleteMarkers);err!=nil{t.Fatal(err)}
	if incompleteMarkers!=1{t.Fatalf("M6.1 incomplete typed window improperly committed: %d",incompleteMarkers)}

	// A capture boundary is durably committed at the end of window zero.
	// After reconnect, its object in window one must recover the exact
	// generation/scope/digest binding and remaining counts from SQL.
	split:=backlogUSNFixture(t,"fi-usn-capture-cross-window.iss.local","split")
	splitRoot:=privateBacklogTestRoot(t)
	for i:=0;i<2;i++{
		if _,err:=MaterializeBacklogWindow(ctx,split,limits,i,splitRoot);err!=nil{t.Fatal(err)}
		if err:=RecordVerifiedBacklogArtifactWindow(ctx,writer,split,limits,i,splitRoot);err!=nil{t.Fatal(err)}
		if err:=StageVerifiedBacklogSourceWindow(ctx,writer,split,limits,i,splitRoot);err!=nil{t.Fatal(err)}
	}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,split,limits,0,splitRoot);err!=nil{
		t.Fatalf("split M6.1 first window failed: %v",err)
	}
	restarted,err:=pgx.ConnectConfig(ctx,writer.Config().Copy())
	if err!=nil{t.Fatal(err)}
	defer restarted.Close(context.Background())
	if err:=StageBacklogTypedWindow(ctx,reader,restarted,split,limits,1,splitRoot);err!=nil{
		t.Fatalf("split M6.1 cross-window restore failed: %v",err)
	}
	if err:=StageBacklogTypedWindow(ctx,reader,restarted,split,limits,1,splitRoot);err!=nil{
		t.Fatalf("split M6.1 replay failed: %v",err)
	}
	var splitMarkers,splitObjects,splitBound,splitCanonical int64
	if err:=restarted.QueryRow(ctx,`
SELECT
 (SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=decode($1,'hex')),
 (SELECT count(*) FROM fi_recovery_projection.usn_object_observation AS o
  JOIN fi_recovery_projection.source_record AS sr ON sr.source_record_id=o.source_record_id
  JOIN fi_recovery_projection.source_batch AS sb ON sb.source_batch_id=sr.source_batch_id
  JOIN fi_recovery_projection.recorded_generation AS rg ON rg.recorded_generation_id=sb.recorded_generation_id
  WHERE rg.source_id=$2),
 (SELECT count(*) FROM fi_recovery_projection.usn_object_observation AS o
  JOIN fi_recovery_projection.source_record AS sr ON sr.source_record_id=o.source_record_id
  JOIN fi_recovery_projection.source_batch AS sb ON sb.source_batch_id=sr.source_batch_id
  JOIN fi_recovery_projection.recorded_generation AS rg ON rg.recorded_generation_id=sb.recorded_generation_id
  WHERE rg.source_id=$2 AND o.source_batch_sha256 IS NOT NULL),
 (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$2)
`,split.ReceiptSHA256,split.Receipt.Descriptor.SourceID).Scan(
        &splitMarkers,&splitObjects,&splitBound,&splitCanonical);err!=nil{t.Fatal(err)}
	if splitMarkers!=2||splitObjects!=4||splitBound!=1||splitCanonical!=0{
		t.Fatalf("split capture SQL mismatch: windows=%d objects=%d bound=%d canonical=%d",
			splitMarkers,splitObjects,splitBound,splitCanonical)
	}
	// More objects than a preceding bound capture permits must roll back the
	// entire second window, retaining only the first durable marker.
	overflow:=backlogUSNFixture(t,"fi-usn-capture-cross-window-overflow.iss.local","split-overflow")
	overflowRoot:=privateBacklogTestRoot(t)
	for i:=0;i<2;i++{
		if _,err:=MaterializeBacklogWindow(ctx,overflow,limits,i,overflowRoot);err!=nil{t.Fatal(err)}
		if err:=RecordVerifiedBacklogArtifactWindow(ctx,writer,overflow,limits,i,overflowRoot);err!=nil{t.Fatal(err)}
		if err:=StageVerifiedBacklogSourceWindow(ctx,writer,overflow,limits,i,overflowRoot);err!=nil{t.Fatal(err)}
	}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,overflow,limits,0,overflowRoot);err!=nil{t.Fatal(err)}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,overflow,limits,1,overflowRoot);err==nil{
		t.Fatal("over-counted split M6.1 capture was accepted")
	}
	var overflowMarkers,overflowBound int64
	if err:=writer.QueryRow(ctx,`
SELECT
 (SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=decode($1,'hex')),
 (SELECT count(*) FROM fi_recovery_projection.usn_object_observation AS o
  JOIN fi_recovery_projection.source_record AS sr ON sr.source_record_id=o.source_record_id
  JOIN fi_recovery_projection.source_batch AS sb ON sb.source_batch_id=sr.source_batch_id
  JOIN fi_recovery_projection.recorded_generation AS rg ON rg.recorded_generation_id=sb.recorded_generation_id
  WHERE rg.source_id=$2 AND o.source_batch_sha256 IS NOT NULL)
`,overflow.ReceiptSHA256,overflow.Receipt.Descriptor.SourceID).Scan(&overflowMarkers,&overflowBound);err!=nil{t.Fatal(err)}
	if overflowMarkers!=1||overflowBound!=0{
		t.Fatalf("over-counted capture leaked second window markers=%d boundObjects=%d",
			overflowMarkers,overflowBound)
	}
	// The final window contains no M6.1 object. Its empty in-memory
	// capture map must not conceal an unfinished earlier committed boundary.
	missing:=backlogUSNFixture(t,"fi-usn-capture-cross-window-missing.iss.local","split-missing")
	missingRoot:=privateBacklogTestRoot(t)
	for i:=0;i<2;i++{
		if _,err:=MaterializeBacklogWindow(ctx,missing,limits,i,missingRoot);err!=nil{t.Fatal(err)}
		if err:=RecordVerifiedBacklogArtifactWindow(ctx,writer,missing,limits,i,missingRoot);err!=nil{t.Fatal(err)}
		if err:=StageVerifiedBacklogSourceWindow(ctx,writer,missing,limits,i,missingRoot);err!=nil{t.Fatal(err)}
	}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,missing,limits,0,missingRoot);err!=nil{t.Fatal(err)}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,missing,limits,1,missingRoot);err==nil||
		!strings.Contains(err.Error(),"incomplete durable capture"){
		t.Fatalf("missing M6.1 object across committed windows not rejected by SQL: %v",err)
	}
	var missingMarkers int64
	if err:=writer.QueryRow(ctx,`
SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=decode($1,'hex')
`,missing.ReceiptSHA256).Scan(&missingMarkers);err!=nil{t.Fatal(err)}
	if missingMarkers!=1{t.Fatalf("missing capture committed final window: markers=%d",missingMarkers)}
	t.Log("PASS: cross-window legacy and M6.1 binding, restart and replay, late rollback, incomplete final capture refusal, split overflow and missing-across-window rollback, zero canonical SoR")
}
