// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "os"
    "path/filepath"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func nativeChange(usn,reason,attributes string,
    file,parent records.NTFSObjectIdentity) records.USNChangeObservation{
    return records.USNChangeObservation{
        MajorVersion:"2",MinorVersion:"0",FileIdentity:file,
        ParentIdentity:parent,USN:usn,Timestamp:"2026-11-28T13:00:00.000000000Z",
        ReasonRaw:reason,SourceInfoRaw:"0",SecurityID:"0",
        FileAttributesRaw:attributes,FileNameUTF16LEBase64URL:"YQA",
    }
}
func nativeHistorySource(t *testing.T)(Cursor,Segment,records.NTFSObjectIdentity,
    []records.USNChangeObservation){
    t.Helper()
    root:=scopeTestIdentity("1")
    dirA:=scopeTestIdentity("2")
    dirB:=scopeTestIdentity("3")
    file:=scopeTestIdentity("4")
    outside:=scopeTestIdentity("99")
    anchor:=exampleAnchor()
    var err error
    anchor.ScopeID,err=VolumeCaptureScopeID(anchor.VolumeIdentity)
    if err!=nil{t.Fatal(err)}
    batch:=exampleBatch(anchor,100,200)
    batch.Records=[]records.USNChangeObservation{
        nativeChange("110","256","16",dirA,root),
        nativeChange("120","256","16",dirB,dirA),
        nativeChange("130","2","32",file,dirB),
        nativeChange("140","4096","16",dirA,root),
        nativeChange("150","2","32",file,dirB),
        nativeChange("160","8192","16",dirA,outside),
        nativeChange("170","2","32",file,dirB),
        nativeChange("175","2","32",file,outside),
    }
    if err:=records.ValidateUSNReadBatch(batch);err!=nil{t.Fatal(err)}
    raw,err:=json.Marshal(batch)
    if err!=nil{t.Fatal(err)}
    sha:=sha256.Sum256(raw)
    seg:=Segment{Name:segmentNameMust("100"),Batch:batch,SHA256:hex.EncodeToString(sha[:])}
    return anchor,seg,root,batch.Records
}
func TestDirectoryIndexProvesOnlySourceNativeNestedAncestryAndReplays(t *testing.T){
    anchor,seg,root,events:=nativeHistorySource(t)
    dir:=t.TempDir()
    // Source segment stays immutable and is independently revalidated on
    // restart; an index alone is never accepted as historical evidence.
    if err:=atomicWrite(filepath.Join(dir,seg.Name),mustJSON(Envelope{
        Version:SchemaVersion,Batch:seg.Batch,Work:DistinctWork(seg.Batch),
        SHA256:seg.SHA256,
    }));err!=nil{t.Fatal(err)}
    h,err:=OpenDirectoryHistoryIndex(dir,anchor)
    if err!=nil{t.Fatal(err)}
    if err:=h.AddSegment(seg);err!=nil{t.Fatal(err)}
    resolver:=h.Resolver("governed-root",seg.Batch.JournalID,root)
    for i,expected:=range []ScopeClass{
        ScopeGoverned,ScopeGoverned,ScopeGoverned,
        ScopeGoverned,ScopeUnresolved,ScopeUnresolved,
        ScopeUnresolved,ScopeUnresolved,
    }{
        p,err:=resolver(events[i])
        if err!=nil||p.Class!=expected||p.Class==ScopeOutside{
            t.Fatalf("unsafe ancestry event %s: %+v %v",events[i].USN,p,err)
        }
    }
    reloaded,err:=OpenDirectoryHistoryIndex(dir,anchor)
    if err!=nil{t.Fatal(err)}
    for _,i:=range []int{2,4,6,7}{
        p1,_:=resolver(events[i])
        p2,err:=reloaded.Resolver("governed-root",seg.Batch.JournalID,root)(events[i])
        if err!=nil||p1!=p2{t.Fatalf("restart altered native-USN ancestry for %s: %+v %+v %v",
            events[i].USN,p1,p2,err)}
    }
    if err:=reloaded.AddSegment(seg);err!=nil{t.Fatal(err)}
    other:=seg
    other.SHA256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    if err:=reloaded.AddSegment(other);!errors.Is(err,ErrCorrupt){
        t.Fatalf("changed original source accepted under same interval: %v",err)
    }
}
func TestDirectoryHistorySourceCorruptionAndWrongJournalFailClosed(t *testing.T){
    anchor,seg,_,_:=nativeHistorySource(t)
    dir:=t.TempDir()
    // Source segment stays immutable and is independently revalidated on
    // restart; an index alone is never accepted as historical evidence.
    if err:=atomicWrite(filepath.Join(dir,seg.Name),mustJSON(Envelope{
        Version:SchemaVersion,Batch:seg.Batch,Work:DistinctWork(seg.Batch),
        SHA256:seg.SHA256,
    }));err!=nil{t.Fatal(err)}
    h,err:=OpenDirectoryHistoryIndex(dir,anchor);if err!=nil{t.Fatal(err)}
    if err:=h.AddSegment(seg);err!=nil{t.Fatal(err)}
    wrong:=anchor
    wrong.JournalID="2000"
    if _,err:=OpenDirectoryHistoryIndex(dir,wrong);!errors.Is(err,ErrConflict){
        t.Fatalf("history index silently crossed journal boundary: %v",err)
    }
    path:=filepath.Join(dir,historyFilePrefix+seg.Name)
    authentic,err:=readHistoryFile(path)
    if err!=nil{t.Fatal(err)}
    if len(authentic.Changes)==0{t.Fatal("missing directory edges")}
    forged:=authentic
    forged.Changes=append([]directoryLinkTransition(nil),authentic.Changes...)
    forged.Changes[0].Parent=scopeTestIdentity("777")
    if err:=atomicWrite(path,mustJSON(forged));err!=nil{t.Fatal(err)}
    if _,err:=OpenDirectoryHistoryIndex(dir,anchor);!errors.Is(err,ErrCorrupt){
        t.Fatalf("forged positive historical ancestry passed source replay: %v",err)
    }
    if err:=os.WriteFile(filepath.Join(dir,historyFilePrefix+seg.Name),
        []byte(`{"Version":"forged"}{}`),0600);err!=nil{t.Fatal(err)}
    if _,err:=OpenDirectoryHistoryIndex(dir,anchor);!errors.Is(err,ErrCorrupt){
        t.Fatalf("corrupt historical evidence was accepted: %v",err)
    }
}
