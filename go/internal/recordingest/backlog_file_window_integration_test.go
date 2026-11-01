//go:build freebsd && fi_backlog_typed_window_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/Iron-Signal-Systems/fi/go/internal/records"
	"github.com/Iron-Signal-Systems/fi/go/internal/spool"
	"github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
	"github.com/jackc/pgx/v5"
)

const backlogFileScope="fi-backlog-file-scope"

func backlogFileUTF16Path(path string) string {
	u:=utf16.Encode([]rune(path))
	data:=make([]byte,len(u)*2)
	for i,v:=range u{binary.LittleEndian.PutUint16(data[i*2:],v)}
	return base64.RawURLEncoding.EncodeToString(data)
}

// A production-shaped observation, with repeatable volume/root/object keys,
// independent file metadata and the normal content hash and child families.
func backlogFileObservation(index int, observed string)(fileObservationPayload,error){
	const rootPath=`C:\FI-Backlog-File`
	const volumeGUID=`\\?\Volume{12345678-1234-1234-1234-123456789abc}\`
	volume:=records.VolumeIdentity{
		MethodVersion:ntfs.IdentityMethodVersion,VolumeGUID:volumeGUID,VolumeSerial:"123456789",
	}
	rootObj:=records.NTFSObjectIdentity{
		MethodVersion:ntfs.IdentityMethodVersion,FileReferenceNumber:"5",SequenceNumber:"1",
	}
	obj:=records.NTFSObjectIdentity{
		MethodVersion:ntfs.IdentityMethodVersion,
		FileReferenceNumber:strconv.Itoa(1000+index),SequenceNumber:"1",
	}
	path:=fmt.Sprintf(`%s\file-%06d.bin`,rootPath,index)
	content:=[]byte(fmt.Sprintf("%016d",index))
	md5sum:=md5.Sum(content);sha1sum:=sha1.Sum(content);sha256sum:=sha256.Sum256(content)
	hashes:=records.ContentHashObservation{
		State:records.ContentHashPresent,BytesHashed:"16",
		MD5:hex.EncodeToString(md5sum[:]),SHA1:hex.EncodeToString(sha1sum[:]),
		SHA256:hex.EncodeToString(sha256sum[:]),
	}
	prefix:=records.ContentPrefixObservation{
		State:records.ContentPrefixPresent,BytesObserved:"16",
		PrefixBase64URL:base64.RawURLEncoding.EncodeToString(content),
	}
	sd:=make([]byte,20);sd[0]=1;sd[3]=0x80
	security,err:=records.ParseSecurityDescriptor(sd)
	if err!=nil{return fileObservationPayload{},err}
	sacl,err:=records.ParseSACLDescriptor(sd)
	if err!=nil{return fileObservationPayload{},err}
	stream:=records.StreamIdentityFromRawUTF16(utf16.Encode([]rune(`::$DATA`)))
	obs:=ntfs.Observation{
		GovernedRoot:records.GovernedRootIdentity{
			ScopeID:backlogFileScope,
			RequestedPathUTF16LEBase64URL:backlogFileUTF16Path(rootPath),
			ResolvedPathUTF16LEBase64URL:backlogFileUTF16Path(rootPath),
			MethodVersion:ntfs.ContainmentMethodVersion,VolumeIdentity:volume,ObjectIdentity:rootObj,
		},
		Containment:records.PathContainment{MethodVersion:ntfs.ContainmentMethodVersion},
		VolumeIdentity:volume,ObjectIdentity:obj,
		ParentBinding:records.ParentObjectBindingFor(rootObj),
		SubjectKind:records.SubjectFile,
		PathBinding:records.PathBinding{
			RequestedPathUTF16LEBase64URL:backlogFileUTF16Path(path),
			ResolvedPathUTF16LEBase64URL:backlogFileUTF16Path(path),
		},
		ObservedAt:observed,
		Metadata:records.MetadataObservation{
			LogicalSize:"16",AllocatedSize:"4096",CreationTime:observed,
			LastWriteTime:observed,ChangeTime:observed,LastAccessTime:observed,
			RawAttributes:"32",LinkCount:"1",
		},
		Security:security,SACL:sacl,
		Reparse:records.ReparseObservation{
			State:records.ReparseStateNotPresent,
			DataState:records.ReparseDataStateNotApplicable,
			DataFormat:records.ReparseDataFormatNotApplicable,
		},
		StreamInventory:records.StreamInventory{
			State:records.ObservationStatePresent,
			Streams:[]records.StreamObservation{{
				Identity:stream,LogicalSize:"16",AllocatedSize:"4096",
			}},
		},
		ContentHashes:&hashes,ContentPrefix:&prefix,
		CollectionEntryMethod:ntfs.CollectionEntryPath,
		CollectionMethod:records.CollectionDirectWindowsNTFS,
		ObservationStatus:records.ObservationComplete,
	}
	return fileObservationPayload{NTFS:obs,ContentHashes:hashes},nil
}

func backlogFileWindowFixture(t *testing.T,source string,badLate bool)*PreparedGeneration{
	t.Helper()
	g:=privateTypedFixture(t,source,false)
	g.Receipt.Descriptor.GenerationID="20261101T140000.000000000Z-file"
	g.Receipt.TransferSHA256=strings.Repeat("9",64)
	g.ReceiptSHA256=strings.Repeat("a",64)
	if badLate{
		g.Receipt.Descriptor.GenerationID="20261101T140001.000000000Z-file-reject"
		g.Receipt.TransferSHA256=strings.Repeat("b",64)
		g.ReceiptSHA256=strings.Repeat("c",64)
	}
	g.Receipt.DataBytes=0
	const observed="2026-11-01T14:00:00.123456789Z"
	for bi:=range g.Batches{
		b:=&g.Batches[bi]
		var data []byte
		for n:=0;n<b.Manifest.RecordCount;n++{
			index:=bi*3+n
			if bi==1&&n==0{index=0} // reobserve original object after restart
			value,err:=backlogFileObservation(index,observed)
			if err!=nil{t.Fatal(err)}
			if badLate&&bi==1&&n==2 {
				// Envelope and batch digests remain valid; the typed file
				// observation must reject this after first-batch COPY.
				value.NTFS.ObservationStatus="invalid-synthetic-status"
			}
			payload,err:=json.Marshal(value)
			if err!=nil{t.Fatal(err)}
			envelope:=spool.Record{
				Version:SpoolRecordVersion,RecordKind:"FileObservation",
				ScopeID:backlogFileScope,WrittenAt:observed,Payload:payload,
			}
			encoded,err:=json.Marshal(envelope)
			if err!=nil{t.Fatal(err)}
			data=append(data,encoded...);data=append(data,'\n')
		}
		path:=filepath.Join(t.TempDir(),"file.jsonl")
		if err:=os.WriteFile(path,data,0600);err!=nil{t.Fatal(err)}
		b.DataPath=path
		b.Manifest.DataBytes=int64(len(data))
		dataSHA:=sha256.Sum256(data)
		b.Manifest.DataSHA256=hex.EncodeToString(dataSHA[:])
		raw,err:=json.Marshal(b.Manifest)
		if err!=nil{t.Fatal(err)}
		b.ManifestRawBytes=raw
		b.ManifestBytes=len(raw)
		manifestSHA:=sha256.Sum256(raw)
		b.ManifestSHA256=hex.EncodeToString(manifestSHA[:])
		g.Receipt.DataBytes+=uint64(len(data))
	}
	return g
}

// Called within TestBacklogTypedWindowIsolatedDurableAtomicity. The parent
// test owns and protects temporary fi_recovery / fi_recovery_projection.
func exerciseBacklogFileWindows(t *testing.T,ctx context.Context,reader,writer *pgx.Conn){
	t.Helper()
	g:=backlogFileWindowFixture(t,"fi-file-window-acceptance.iss.local",false)
	root:=privateBacklogTestRoot(t)
	limits:=BacklogWindowLimits{MaxRecords:3,MaxDataBytes:1<<20}
	for i:=0;i<2;i++{
		if _,err:=MaterializeBacklogWindow(ctx,g,limits,i,root);err!=nil{t.Fatal(err)}
		if err:=RecordVerifiedBacklogArtifactWindow(ctx,writer,g,limits,i,root);err!=nil{t.Fatal(err)}
		if err:=StageVerifiedBacklogSourceWindow(ctx,writer,g,limits,i,root);err!=nil{t.Fatal(err)}
	}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,g,limits,1,root);err==nil{
		t.Fatal("file window 1 committed without window 0")
	}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,g,limits,0,root);err!=nil{t.Fatal(err)}
	resumed,err:=pgx.ConnectConfig(ctx,writer.Config().Copy())
	if err!=nil{t.Fatal(err)}
	defer resumed.Close(context.Background())
	if err:=StageBacklogTypedWindow(ctx,reader,resumed,g,limits,0,root);err!=nil{
		t.Fatalf("file window zero reprocessing was not idempotent: %v",err)
	}
	if err:=StageBacklogTypedWindow(ctx,reader,resumed,g,limits,1,root);err!=nil{t.Fatal(err)}

	var fileRows,metadataRows,hashRows,prefixRows,inventoryRows,streamRows,securityRows,saclRows,sourceRows,markers,volumeRows,objectRows,rootRows,canonical int64
	err=resumed.QueryRow(ctx,`
SELECT
 (SELECT count(*) FROM fi_recovery_projection.file_observation fo
 JOIN fi_recovery_projection.source_record sr USING(source_record_id)
 JOIN fi_recovery_projection.source_batch sb USING(source_batch_id)
 JOIN fi_recovery_projection.recorded_generation rg USING(recorded_generation_id)
 WHERE rg.source_id=$1),
 (SELECT count(*) FROM fi_recovery_projection.file_metadata_observation),
 (SELECT count(*) FROM fi_recovery_projection.content_hash_observation),
 (SELECT count(*) FROM fi_recovery_projection.content_prefix_observation),
 (SELECT count(*) FROM fi_recovery_projection.stream_inventory),
 (SELECT count(*) FROM fi_recovery_projection.stream_observation),
 (SELECT count(*) FROM fi_recovery_projection.security_observation),
 (SELECT count(*) FROM fi_recovery_projection.sacl_observation),
 (SELECT count(*) FROM fi_recovery_projection.source_record sr
 JOIN fi_recovery_projection.source_batch sb USING(source_batch_id)
 JOIN fi_recovery_projection.recorded_generation rg USING(recorded_generation_id)
 WHERE rg.source_id=$1),
 (SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=decode($2,'hex')),
 (SELECT count(*) FROM fi_recovery_projection.ntfs_volume WHERE source_id=$1),
 (SELECT count(*) FROM fi_recovery_projection.ntfs_object),
 (SELECT count(*) FROM fi_recovery_projection.governed_root WHERE source_id=$1),
 (SELECT count(*) FROM fi.recorded_generation WHERE source_id=$1)
`,g.Receipt.Descriptor.SourceID,g.ReceiptSHA256).Scan(
		&fileRows,&metadataRows,&hashRows,&prefixRows,&inventoryRows,&streamRows,
		&securityRows,&saclRows,&sourceRows,&markers,&volumeRows,&objectRows,&rootRows,&canonical)
	if err!=nil{t.Fatal(err)}
	if fileRows!=6||metadataRows!=6||hashRows!=6||prefixRows!=6||
		inventoryRows!=6||streamRows!=6||securityRows!=6||saclRows!=6||
		sourceRows!=6||markers!=2||volumeRows!=1||objectRows!=6||
		rootRows!=1||canonical!=0{
		t.Fatalf("STOP: file=%d metadata=%d hashes=%d prefix=%d inventory=%d stream=%d security=%d sacl=%d source=%d marker=%d volumes=%d objects=%d roots=%d canonical=%d",
			fileRows,metadataRows,hashRows,prefixRows,inventoryRows,streamRows,securityRows,saclRows,
			sourceRows,markers,volumeRows,objectRows,rootRows,canonical)
	}

	bad:=backlogFileWindowFixture(t,"fi-file-window-rejected.iss.local",true)
	badRoot:=privateBacklogTestRoot(t)
	badLimits:=BacklogWindowLimits{MaxRecords:6,MaxDataBytes:1<<20}
	if _,err:=MaterializeBacklogWindow(ctx,bad,badLimits,0,badRoot);err!=nil{t.Fatal(err)}
	if err:=RecordVerifiedBacklogArtifactWindow(ctx,writer,bad,badLimits,0,badRoot);err!=nil{t.Fatal(err)}
	if err:=StageVerifiedBacklogSourceWindow(ctx,writer,bad,badLimits,0,badRoot);err!=nil{t.Fatal(err)}
	if err:=StageBacklogTypedWindow(ctx,reader,writer,bad,badLimits,0,badRoot);err==nil{
		t.Fatal("late invalid FileObservation was accepted after earlier source-batch flush")
	}
	var leakedGeneration,leakedMarkers int64
	err=writer.QueryRow(ctx,`
SELECT (SELECT count(*) FROM fi_recovery_projection.recorded_generation WHERE source_id=$1),
       (SELECT count(*) FROM fi_recovery.typed_window WHERE receipt_sha256=decode($2,'hex'))
`,bad.Receipt.Descriptor.SourceID,bad.ReceiptSHA256).Scan(&leakedGeneration,&leakedMarkers)
	if err!=nil{t.Fatal(err)}
	if leakedGeneration!=0||leakedMarkers!=0{
		t.Fatalf("STOP: failed FileObservation transaction leaked shadow generation=%d marker=%d",
			leakedGeneration,leakedMarkers)
	}
	t.Log("PASS: 6 file observations and children, shared NTFS root/volume/object identity across 2 typed windows, restart, late rollback, zero authoritative SoR")
}
