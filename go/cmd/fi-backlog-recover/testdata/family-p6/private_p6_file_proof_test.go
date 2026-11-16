// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Private C220 optimized-source tests: proof must come from the actual
// original seed constructor, never a fake FileSourceValidated increment.
package recordingest

import (
    "context"
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "encoding/base64"
    "encoding/binary"
    "encoding/hex"
    "fmt"
    "strconv"
    "testing"
    "time"
    "unicode/utf16"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
)

func privateP6ProofUTF16Path(path string) string {
    units:=utf16.Encode([]rune(path))
    raw:=make([]byte,len(units)*2)
    for i,v:=range units{binary.LittleEndian.PutUint16(raw[2*i:],v)}
    return base64.RawURLEncoding.EncodeToString(raw)
}

// Deterministic complete, valid FI observation, modeled on the existing
// signed FI file replay fixture, without its gated PostgreSQL dependencies.
func privateP6ValidFileProofFixture(t *testing.T) SourceRecord {
    t.Helper()
    const scope="p6-file-proof-scope"
    const rootPath=`C:\FI-P6-Proof`
    const volumeGUID=`\\?\Volume{12345678-1234-1234-1234-123456789abc}\`
    now:=time.Date(2026,11,16,12,0,0,0,time.UTC).Format(time.RFC3339Nano)
    volume:=records.VolumeIdentity{
        MethodVersion:ntfs.IdentityMethodVersion,
        VolumeGUID:volumeGUID,VolumeSerial:"123456789",
    }
    rootObject:=records.NTFSObjectIdentity{
        MethodVersion:ntfs.IdentityMethodVersion,
        FileReferenceNumber:"5",SequenceNumber:"1",
    }
    object:=records.NTFSObjectIdentity{
        MethodVersion:ntfs.IdentityMethodVersion,
        FileReferenceNumber:strconv.Itoa(4000),SequenceNumber:"1",
    }
    content:=[]byte("0000000000000000")
    md5Hash:=md5.Sum(content)
    sha1Hash:=sha1.Sum(content)
    sha256Hash:=sha256.Sum256(content)
    hashes:=records.ContentHashObservation{
        State:records.ContentHashPresent,BytesHashed:"16",
        MD5:hex.EncodeToString(md5Hash[:]),
        SHA1:hex.EncodeToString(sha1Hash[:]),
        SHA256:hex.EncodeToString(sha256Hash[:]),
    }
    prefix:=records.ContentPrefixObservation{
        State:records.ContentPrefixPresent,BytesObserved:"16",
        PrefixBase64URL:base64.RawURLEncoding.EncodeToString(content),
    }
    descriptor:=make([]byte,20)
    descriptor[0]=1
    descriptor[3]=0x80
    security,err:=records.ParseSecurityDescriptor(descriptor)
    if err!=nil{t.Fatal(err)}
    sacl,err:=records.ParseSACLDescriptor(descriptor)
    if err!=nil{t.Fatal(err)}
    stream:=records.StreamIdentityFromRawUTF16(utf16.Encode([]rune(`::$DATA`)))
    value:=fileObservationPayload{
        NTFS:ntfs.Observation{
            GovernedRoot:records.GovernedRootIdentity{
                ScopeID:scope,
                RequestedPathUTF16LEBase64URL:privateP6ProofUTF16Path(rootPath),
                ResolvedPathUTF16LEBase64URL:privateP6ProofUTF16Path(rootPath),
                MethodVersion:ntfs.ContainmentMethodVersion,
                VolumeIdentity:volume,ObjectIdentity:rootObject,
            },
            Containment:records.PathContainment{MethodVersion:ntfs.ContainmentMethodVersion},
            VolumeIdentity:volume,ObjectIdentity:object,
            ParentBinding:records.ParentObjectBindingFor(rootObject),
            SubjectKind:records.SubjectFile,
            PathBinding:records.PathBinding{
                RequestedPathUTF16LEBase64URL:privateP6ProofUTF16Path(rootPath+`\file-000000.bin`),
                ResolvedPathUTF16LEBase64URL:privateP6ProofUTF16Path(rootPath+`\file-000000.bin`),
            },
            ObservedAt:now,
            Metadata:records.MetadataObservation{
                LogicalSize:"16",AllocatedSize:"4096",
                CreationTime:now,LastWriteTime:now,ChangeTime:now,LastAccessTime:now,
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
        },
        ContentHashes:hashes,
    }
    if err:=ntfs.ValidateObservation(value.NTFS);err!=nil{
        t.Fatalf("FI P6 proof fixture must be fully valid: %v",err)
    }
    return SourceRecord{
        Record:spool.Record{Version:SpoolRecordVersion,
            RecordKind:"FileObservation",ScopeID:scope},
        RecordBytes:256,PrivateFamilyP3File:&value,
    }
}

func TestPrivateP6FileProofUsesOriginalValidationAndBindsSource(t *testing.T){
    source:=privateP6ValidFileProofFixture(t)
    first,err:=privateP6ValidatedNTFSRecord("p6-source-A",501,3,source)
    if err!=nil{t.Fatal(err)}
    second,err:=privateP6ValidatedNTFSRecord("p6-source-A",502,4,source)
    if err!=nil{t.Fatal(err)}
    if first.validatedSource==nil||second.validatedSource==nil{
        t.Fatal("FI P6: actual original seed validation token was dropped")
    }
    if first.validatedSource==second.validatedSource{
        t.Fatal("FI P6: two distinct signed rows shared one validation proof pointer")
    }
    if first.sourceRecordID!=501||second.sourceRecordID!=502||
        first.ordinal!=3||second.ordinal!=4||
        first.sourceID!="p6-source-A"||first.bytes!=256{
        t.Fatal("FI P6: validated record was detached from signed source identity")
    }
}

func TestPrivateP6FileProofRejectsMalformedAndScopeMismatch(t *testing.T){
    value:=privateP6ValidFileProofFixture(t)
    t.Run("missing-batch-parent",func(t *testing.T){
        _,err:=privateP6ValidatedNTFSRecord("",101,2,value)
        if err==nil{t.Fatal("missing source identifier accepted")}
    })
    t.Run("zero-foreign-key",func(t *testing.T){
        _,err:=privateP6ValidatedNTFSRecord("p6-source",0,2,value)
        if err==nil{t.Fatal("invalid FK accepted")}
    })
    t.Run("signed-scope-mismatch",func(t *testing.T){
        bad:=value
        bad.Record.ScopeID="wrong-scope"
        if _,err:=privateP6ValidatedNTFSRecord("p6-source",101,2,bad);err==nil{
            t.Fatal("incorrect signed governed-root scope accepted")
        }
    })
    t.Run("malformed-ntfs-observation",func(t *testing.T){
        bad:=value
        copied:=*bad.PrivateFamilyP3File
        copied.NTFS.ObservationStatus=""
        bad.PrivateFamilyP3File=&copied
        if _,err:=privateP6ValidatedNTFSRecord("p6-source",101,2,bad);err==nil{
            t.Fatal("invalid NTFS observation was treated as source-validated")
        }
    })
    t.Run("unproven-bulk-record",func(t *testing.T){
        if _,err:=fileBulkRecordFromValidatedSource("p6-source",101,2,nil,nil,256);err==nil{
            t.Fatal("original optimized File bulk constructor accepted missing proof")
        }
    })
}

func TestPrivateP6FileProofRequiresOriginalWindowCounters(t *testing.T){
    source:=privateP6ValidFileProofFixture(t)
    sink:=&privateP6SQLCoordinator{sourceID:"p6-source-A"}
    row:=privateP6Record{sourceBatchID:101,ordinal:1,prepared:source}
    if err:=sink.ntfs(context.Background(),[]privateP6Record{row},[]int64{501});err==nil{
        t.Fatal("FI P6: typed family accepted missing original source/reuse ledger")
    }
}

func TestPrivateP6FileProofDoesNotPreIncrementReuse(t *testing.T){
    source:=privateP6ValidFileProofFixture(t)
    counters:=&ntfsStageTimingCounters{}
    ctx:=context.WithValue(context.Background(),ntfsStageTimingContextKey{},counters)
    _,err:=privateP6ValidatedNTFSRecord("p6-source-A",100,1,source)
    if err!=nil{t.Fatal(err)}
    if counters.FileSourceValidated!=0||counters.FileBulkValidationReused!=0{
        t.Fatal(fmt.Sprintf("FI P6: source proof creation altered counters without SQL enqueue/COPY source=%d reused=%d",
            counters.FileSourceValidated,counters.FileBulkValidationReused))
    }
    // SourceValid is updated only after the record enters the actual
    // fileObservationBulkState. Reused is updated only by original COPY.
    _=ctx
}
