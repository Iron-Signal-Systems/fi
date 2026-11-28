// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "bytes"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "reflect"
    "sort"
    "strconv"
    "strings"
    "sync"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const (
    historyIndexVersion = "fi-usn-history-directory-transitions/1"
    historyFilePrefix = "directory-history-"
    ntfsAttributeDirectory = 0x10
    ntfsAttributeReparse = 0x400
    usnReasonFileDelete = 0x00000200
    usnReasonRenameOldName = 0x00001000
    usnReasonHardLinkChange = 0x00010000
)

type directoryLinkTransition struct {
    EventUSN string
    Directory records.NTFSObjectIdentity
    Parent records.NTFSObjectIdentity
    LinkKnown bool
}
type directorySegmentHistory struct {
    Version string
    CaptureScopeID string
    JournalID string
    VolumeIdentity records.VolumeIdentity
    SourceBatchSHA256 string
    StartUSN string
    NextUSN string
    Changes []directoryLinkTransition
}
type indexedDirectoryTransition struct {
    usn uint64
    parent records.NTFSObjectIdentity
    known bool
}

// DirectoryHistoryIndex is a forward-only native-USN directory-transition
// ledger. It does not sample current NTFS paths, infer unknown baseline links,
// assume complete hard-link coverage or authorize source exclusions.
// Segments persist before FI spool publication; replay is source-hash bound.
type DirectoryHistoryIndex struct {
    mu sync.RWMutex
    dir string
    anchor Cursor
    seen map[string]string
    transitions map[records.NTFSObjectIdentity][]indexedDirectoryTransition
}

func historyPath(dir string,seg Segment)string{
    return filepath.Join(dir,historyFilePrefix+seg.Name)
}

// OpenDirectoryHistoryIndex replays ONLY immutable directory transitions,
// not all historical file changes. Large 20M-file source workloads therefore
// do not require keeping every original USN event in the correlation index.
func OpenDirectoryHistoryIndex(dir string,anchor Cursor)(*DirectoryHistoryIndex,error){
    if !filepath.IsAbs(dir){return nil,errors.New("history index needs absolute original source custody path")}
    if err:=validateCursor(anchor);err!=nil{return nil,err}
    h:=&DirectoryHistoryIndex{
        dir:dir,anchor:anchor,
        seen:make(map[string]string),
        transitions:make(map[records.NTFSObjectIdentity][]indexedDirectoryTransition),
    }
    entries,err:=os.ReadDir(dir)
    if err!=nil{return nil,err}
    names:=make([]string,0,128)
    for _,entry:=range entries{
        if !strings.HasPrefix(entry.Name(),historyFilePrefix){continue}
        if !strings.HasSuffix(entry.Name(),".json") || !entry.Type().IsRegular(){
            return nil,fmt.Errorf("%w: malformed or nonregular historical directory entry %q",ErrCorrupt,entry.Name())
        }
        names=append(names,entry.Name())
    }
    sort.Strings(names)
    for _,name:=range names{
        v,err:=readHistoryFile(filepath.Join(dir,name))
        if err!=nil{return nil,err}
        if name!=historyFilePrefix+segmentNameMust(v.StartUSN) {
            return nil,fmt.Errorf("%w: history segment filename diverges from source interval",ErrCorrupt)
        }
        if !historyMatchesAnchor(anchor,v){
            return nil,fmt.Errorf("%w: directory history changed original NTFS source identity",ErrConflict)
        }
        if _,ok:=h.seen[v.StartUSN];ok{
            return nil,fmt.Errorf("%w: duplicate original directory history",ErrCorrupt)
        }
        if err:=h.applyLocked(v);err!=nil{return nil,err}
    }
    return h,nil
}

func historyMatchesAnchor(anchor Cursor,v directorySegmentHistory)bool{
    return v.Version==historyIndexVersion &&
        v.CaptureScopeID==anchor.ScopeID &&
        v.JournalID==anchor.JournalID &&
        reflect.DeepEqual(v.VolumeIdentity,anchor.VolumeIdentity)
}
func readHistoryFile(path string)(directorySegmentHistory,error){
    info,err:=os.Lstat(path)
    if err!=nil{return directorySegmentHistory{},err}
    if !info.Mode().IsRegular()||info.Size()==0||info.Size()>maxEnvelopeBytes{
        return directorySegmentHistory{},fmt.Errorf("%w: invalid original directory history file",ErrCorrupt)
    }
    raw,err:=os.ReadFile(path)
    if err!=nil{return directorySegmentHistory{},err}
    reader:=json.NewDecoder(bytes.NewReader(raw))
    reader.DisallowUnknownFields()
    var v directorySegmentHistory
    if err:=reader.Decode(&v);err!=nil{return v,fmt.Errorf("%w: invalid history: %v",ErrCorrupt,err)}
    var trailing any
    if err:=reader.Decode(&trailing);err!=io.EOF{
        return v,fmt.Errorf("%w: trailing directory history",ErrCorrupt)
    }
    if _,err:=parseHistorySource(v);err!=nil{return v,err}
    return v,nil
}
func parseHistorySource(v directorySegmentHistory)(uint64,error){
    start,err:=strconv.ParseUint(v.StartUSN,10,64)
    if err!=nil{return 0,fmt.Errorf("%w: history start USN",ErrCorrupt)}
    end,err:=strconv.ParseUint(v.NextUSN,10,64)
    if err!=nil||end<=start{return 0,fmt.Errorf("%w: history next USN",ErrCorrupt)}
    if len(v.SourceBatchSHA256)!=64{
        return 0,fmt.Errorf("%w: missing original source digest",ErrCorrupt)
    }
    previous:=start
    for _,change:=range v.Changes{
        n,err:=strconv.ParseUint(change.EventUSN,10,64)
        if err!=nil||n<start||n>=end||n<previous{
            return 0,fmt.Errorf("%w: unordered/out-of-window directory USN",ErrCorrupt)
        }
        if err:=records.ValidateNTFSObjectIdentity(change.Directory);err!=nil{return 0,err}
        if change.LinkKnown{
            if err:=records.ValidateNTFSObjectIdentity(change.Parent);err!=nil{return 0,err}
        }
        previous=n
    }
    return start,nil
}

// AddSegment durably indexes only source-native directory link transitions.
// Re-applying a source batch is idempotent ONLY for the same original SHA-256.
// It cannot change the source cursor or cause USN re-observation.
func (h *DirectoryHistoryIndex) AddSegment(seg Segment)error{
    if h==nil{return errors.New("FI directory history must be open")}
    h.mu.Lock()
    defer h.mu.Unlock()
    if seg.SHA256=="" || !matchesBatch(h.anchor,seg.Batch)||
        seg.Name!=segmentNameMust(seg.Batch.StartUSN){
        return fmt.Errorf("%w: unverified or foreign original source history",ErrConflict)
    }
    v:=directorySegmentHistory{
        Version:historyIndexVersion,CaptureScopeID:seg.Batch.ScopeID,
        JournalID:seg.Batch.JournalID,VolumeIdentity:seg.Batch.VolumeIdentity,
        SourceBatchSHA256:seg.SHA256,
        StartUSN:seg.Batch.StartUSN,NextUSN:seg.Batch.NextUSN,
        Changes:make([]directoryLinkTransition,0),
    }
    observedInSegment:=make(map[records.NTFSObjectIdentity]bool)
    for _,change:=range seg.Batch.Records{
        reason,err:=strconv.ParseUint(change.ReasonRaw,10,32)
        if err!=nil{return fmt.Errorf("%w: directory record reason not decimal",ErrCorrupt)}
        attrs,err:=strconv.ParseUint(change.FileAttributesRaw,10,32)
        if err!=nil{return fmt.Errorf("%w: directory record attributes not decimal",ErrCorrupt)}
        hasKnownLink:=attrs&ntfsAttributeDirectory!=0 && attrs&ntfsAttributeReparse==0
        knownPreviously:=len(h.transitions[change.FileIdentity])>0||
            observedInSegment[change.FileIdentity]
        // A previously known directory may be deleted/renamed with missing
        // attribute bits. Conservatively retire its previous positive link.
        removed:=reason&(usnReasonFileDelete|usnReasonRenameOldName|usnReasonHardLinkChange)!=0
        if !hasKnownLink && !(removed&&knownPreviously){continue}
        v.Changes=append(v.Changes,directoryLinkTransition{
            EventUSN:change.USN,Directory:change.FileIdentity,
            Parent:change.ParentIdentity,LinkKnown:hasKnownLink&&!removed,
        })
        observedInSegment[change.FileIdentity]=true
    }
    if _,err:=parseHistorySource(v);err!=nil{return err}
    if existing,ok:=h.seen[v.StartUSN];ok{
        if existing!=v.SourceBatchSHA256{
            return fmt.Errorf("%w: directory history source batch changed",ErrCorrupt)
        }
        stored,err:=readHistoryFile(historyPath(h.dir,seg))
        if err!=nil{return err}
        if !reflect.DeepEqual(stored,v){
            return fmt.Errorf("%w: original directory history changed or missing evidence",ErrCorrupt)
        }
        return nil
    }
    path:=historyPath(h.dir,seg)
    if _,err:=os.Lstat(path);err==nil{
        return fmt.Errorf("%w: untracked original directory history already exists",ErrCorrupt)
    }else if !errors.Is(err,os.ErrNotExist){return err}
    raw,err:=json.Marshal(v)
    if err!=nil{return err}
    if len(raw)>int(maxEnvelopeBytes){return fmt.Errorf("%w: directory history segment too large",ErrCapacity)}
    if err:=atomicWrite(path,raw);err!=nil{return err}
    return h.applyLocked(v)
}

func (h *DirectoryHistoryIndex) applyLocked(v directorySegmentHistory)error{
    if !historyMatchesAnchor(h.anchor,v){return fmt.Errorf("%w: directory index original source mismatch",ErrConflict)}
    if _,err:=parseHistorySource(v);err!=nil{return err}
    if _,found:=h.seen[v.StartUSN];found{return fmt.Errorf("%w: duplicate historical source",ErrCorrupt)}
    for _,change:=range v.Changes{
        n,_:=strconv.ParseUint(change.EventUSN,10,64)
        prior:=h.transitions[change.Directory]
        if len(prior)>0 && n<prior[len(prior)-1].usn{
            return fmt.Errorf("%w: directory history USNs moved backwards",ErrCorrupt)
        }
        h.transitions[change.Directory]=append(prior,indexedDirectoryTransition{
            usn:n,parent:change.Parent,known:change.LinkKnown,
        })
    }
    h.seen[v.StartUSN]=v.SourceBatchSHA256
    return nil
}

// Resolver constructs proof for positive ancestry ONLY. An object outside
// the known directory graph remains Unresolved, never ProvenOutside, even
// if it presently resides somewhere else. Exact NTFS sequence identities
// prevent inherited ancestry on File-ID reuse.
func (h *DirectoryHistoryIndex) Resolver(scope,journal string,root records.NTFSObjectIdentity)ScopeResolver{
    return func(change records.USNChangeObservation)(ScopeEvidence,error){
        if h==nil{return ScopeEvidence{},errors.New("missing verified history index")}
        evidence:=ScopeEvidence{
            Class:ScopeUnresolved,ScopeID:scope,JournalID:journal,
            RootIdentity:root,FileIdentity:change.FileIdentity,
            ParentIdentity:change.ParentIdentity,EventUSN:change.USN,
        }
        usn,err:=strconv.ParseUint(change.USN,10,64)
        if err!=nil{return evidence,err}
        h.mu.RLock()
        known:=change.ParentIdentity==root||h.ancestorLocked(change.ParentIdentity,root,usn)
        h.mu.RUnlock()
        if known{
            evidence.Class=ScopeGoverned
            evidence.HistoricalAncestry=true
            evidence.Reason="OriginalUSNDirectoryAncestry"
        }
        return evidence,nil
    }
}
func (h *DirectoryHistoryIndex) ancestorLocked(
    current,root records.NTFSObjectIdentity,usn uint64,
)bool{
    seen:=make(map[records.NTFSObjectIdentity]struct{},16)
    for depth:=0;depth<256;depth++{
        if current==root{return true}
        if _,cycle:=seen[current];cycle{return false}
        seen[current]=struct{}{}
        history:=h.transitions[current]
        if len(history)==0{return false}
        pos:=sort.Search(len(history),func(i int)bool{return history[i].usn>usn})
        if pos==0{return false}
        edge:=history[pos-1]
        if !edge.known{return false}
        current=edge.parent
    }
    return false
}
