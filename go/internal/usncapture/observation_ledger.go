// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "bufio"
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "sort"
    "path/filepath"
    "strconv"
    "strings"
    "sync"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

const (
    observationCursorName="observation.json"
    observationReceiptPrefix="observation-receipt-"
    observationProofVersion="fi-usn-observation-published/1"
    observationIntentPrefix="observation-intent-"
)
var ErrObservationPending=errors.New("FI source observation requires original verified NTFS evidence")
var ErrAmbiguousObservation=errors.New("FI independent NTFS observation publication outcome is ambiguous")

// ObservationLedger is an independent source consumer: it never moves the raw
// capture cursor or the USNScopedCapture processed cursor. Its original
// immutable NTFS interval remains available to both downstream lanes.
type ObservationLedger struct {
    mu sync.Mutex
    store *Store
    cursor Cursor
}
type observationReceipt struct {
    Version string `json:"version"`
    StartUSN string `json:"start_usn"`
    NextUSN string `json:"next_usn"`
    SourceBatchSHA256 string `json:"source_batch_sha256"`
    Proof string `json:"proof"`
}

// InitializeObservationCursor is exclusive: an earlier FI observation cursor
// must never be rebased to a later journal head after crash or reinstall.
// Bootstrap establishes it at the SAME original pre-baseline USN anchor.
func InitializeObservationCursor(dir string,anchor Cursor)error{
    if !filepath.IsAbs(dir){return errors.New("FI observation queue path must be absolute")}
    if err:=validateCursor(anchor);err!=nil{return err}
    path:=filepath.Join(dir,observationCursorName)
    if _,err:=os.Lstat(path);err==nil{
        return fmt.Errorf("%w: FI observation cursor already exists",ErrConflict)
    }else if !errors.Is(err,os.ErrNotExist){return err}
    return atomicWrite(path,mustJSON(anchor))
}

func OpenObservationLedger(source *Store)(*ObservationLedger,error){
    if source==nil{return nil,errors.New("FI observation ledger needs original raw source")}
    cursor,err:=readCursor(filepath.Join(source.dir,observationCursorName))
    if err!=nil{return nil,fmt.Errorf("load independent observation cursor: %w",err)}
    capture:=source.CaptureCursor()
    if !sameIdentity(cursor,capture){return nil,fmt.Errorf("%w: independent observation source identity",ErrConflict)}
    a,_:=strictDecimalUSN(cursor.NextUSN)
    b,_:=strictDecimalUSN(capture.NextUSN)
    if a>b{return nil,fmt.Errorf("%w: independent observation moved beyond raw source",ErrConflict)}
    ledger:=&ObservationLedger{store:source,cursor:cursor}
    if err:=ledger.recoverReceiptsLocked();err!=nil{return nil,err}
    return ledger,nil
}
func strictDecimalUSN(s string)(uint64,error){
    if !canonicalDecimal(s){return 0,fmt.Errorf("%w: invalid canonical observation USN",ErrCorrupt)}
    return strconvParseUint(s)
}
func strconvParseUint(s string)(uint64,error){
    return strconv.ParseUint(s,10,64)
}
func (l *ObservationLedger) Cursor()Cursor{
    l.mu.Lock();defer l.mu.Unlock()
    return l.cursor
}
func (l *ObservationLedger) nextLocked()(Segment,bool,error){
    l.store.mu.Lock()
    defer l.store.mu.Unlock()
    if !sameIdentity(l.cursor,l.store.capture){
        return Segment{},false,fmt.Errorf("%w: observation source changed",ErrConflict)
    }
    if l.cursor.NextUSN==l.store.capture.NextUSN{return Segment{},false,nil}
    name:=segmentNameMust(l.cursor.NextUSN)
    seg,err:=l.store.loadSegmentLocked(name)
    if errors.Is(err,os.ErrNotExist){
        return Segment{},false,fmt.Errorf("%w: original source %s missing for observations",ErrGap,name)
    }
    if err!=nil{return Segment{},false,err}
    if seg.Batch.StartUSN!=l.cursor.NextUSN {
        return Segment{},false,fmt.Errorf("%w: observation source interval diverged",ErrCorrupt)
    }
    return seg,true,nil
}
func (l *ObservationLedger) Next()(Segment,bool,error){
    if l==nil{return Segment{},false,errors.New("no observation ledger")}
    l.mu.Lock();defer l.mu.Unlock()
    seg,ok,err:=l.nextLocked()
    if err!=nil||!ok{return seg,ok,err}
    if _,err:=os.Lstat(filepath.Join(l.store.dir,observationIntentPrefix+seg.Name));err==nil{
        return Segment{},false,ErrAmbiguousObservation
    }else if !errors.Is(err,os.ErrNotExist){return Segment{},false,err}
    if _,err:=os.Lstat(filepath.Join(l.store.dir,observationReceiptPrefix+seg.Name));err==nil{
        // The receipt is processed by OpenObservationLedger recovery, never
        // ignored and never automatically overwritten.
        return Segment{},false,fmt.Errorf("%w: observation receipt needs restart recovery",ErrCorrupt)
    }else if !errors.Is(err,os.ErrNotExist){return Segment{},false,err}
    return seg,true,nil
}

type ObservationPublicationProof struct {
    receipt string
    sourceSHA string
    startUSN string
    nextUSN string
    spoolPublished bool
}
func (p ObservationPublicationProof) Receipt()string{return p.receipt}

// CommitObservation advances ONLY the independent observation cursor and ONLY
// for a proof created from verified original spool publications (or a
// reproducible bounded zero-candidate policy). It never deletes source facts.
func (l *ObservationLedger) CommitObservation(seg Segment,p ObservationPublicationProof)error{
    if l==nil{return errors.New("no observation ledger")}
    l.mu.Lock();defer l.mu.Unlock()
    if p.sourceSHA!=seg.SHA256||p.startUSN!=seg.Batch.StartUSN||
        p.nextUSN!=seg.Batch.NextUSN||p.receipt==""{
        return fmt.Errorf("%w: independent observation proof does not match original source",ErrConflict)
    }
    current,ok,err:=l.nextLocked()
    if err!=nil{return err}
    if !ok||current.SHA256!=seg.SHA256||current.Batch.NextUSN!=seg.Batch.NextUSN{
        return fmt.Errorf("%w: observation commit cannot skip immutable source",ErrConflict)
    }
    if !validObservationProof(p.receipt){
        return errors.New("independent observation needs verified FI evidence")
    }
    // No positive observation may advance if it was published without the
    // prior durable original-source interval intent. A crash after finalizing
    // FI spool custody but before the receipt must never silently replay.
    if p.spoolPublished{
        data,err:=os.ReadFile(filepath.Join(l.store.dir,observationIntentPrefix+seg.Name))
        if err!=nil{return fmt.Errorf("%w: missing observation publication intent: %v",
            ErrAmbiguousObservation,err)}
        var intent observationReceipt
        if err:=json.Unmarshal(data,&intent);err!=nil{return err}
        if intent.SourceBatchSHA256!=seg.SHA256 || intent.StartUSN!=seg.Batch.StartUSN ||
            intent.NextUSN!=seg.Batch.NextUSN || intent.Version!=SchemaVersion {
            return fmt.Errorf("%w: observation intent source mismatch",ErrCorrupt)
        }
    }
    receipt:=observationReceipt{
        Version:SchemaVersion,StartUSN:seg.Batch.StartUSN,NextUSN:seg.Batch.NextUSN,
        SourceBatchSHA256:seg.SHA256,Proof:p.receipt,
    }
    if err:=atomicWrite(filepath.Join(l.store.dir,observationReceiptPrefix+seg.Name),
        mustJSON(receipt));err!=nil{return err}
    next:=l.cursor
    next.NextUSN=seg.Batch.NextUSN
    if err:=atomicWrite(filepath.Join(l.store.dir,observationCursorName),mustJSON(next));err!=nil{return err}
    l.cursor=next
    return nil
}

func validObservationProof(s string)bool{
    prefix:=observationProofVersion+":"
    if !strings.HasPrefix(s,prefix)||len(s)!=len(prefix)+64{return false}
    decoded,err:=hex.DecodeString(strings.TrimPrefix(s,prefix))
    return err==nil&&len(decoded)==32
}

// Recover a durable observation receipt written just BEFORE a cursor crash.
// The receipt cannot be projected from an unrelated interval or altered
// source; its hash is a local proof, not downstream receiver acceptance.
func (l *ObservationLedger) recoverReceiptsLocked()error{
    for {
        seg,ok,err:=l.nextLocked()
        if err!=nil||!ok{return err}
        path:=filepath.Join(l.store.dir,observationReceiptPrefix+seg.Name)
        info,err:=os.Lstat(path)
        if errors.Is(err,os.ErrNotExist){return nil}
        if err!=nil{return err}
        if !info.Mode().IsRegular()||info.Size()>4096{
            return fmt.Errorf("%w: invalid observation receipt type/size",ErrCorrupt)
        }
        raw,err:=os.ReadFile(path);if err!=nil{return err}
        dec:=json.NewDecoder(bytes.NewReader(raw))
        dec.DisallowUnknownFields()
        var r observationReceipt
        if err:=dec.Decode(&r);err!=nil{return fmt.Errorf("%w: invalid observation receipt: %v",ErrCorrupt,err)}
        var trailing any
        if err:=dec.Decode(&trailing);err!=io.EOF{
            return fmt.Errorf("%w: trailing observation receipt",ErrCorrupt)
        }
        if r.Version!=SchemaVersion||r.StartUSN!=seg.Batch.StartUSN||
            r.NextUSN!=seg.Batch.NextUSN||r.SourceBatchSHA256!=seg.SHA256||
            !validObservationProof(r.Proof){
            return fmt.Errorf("%w: receipt cannot prove original observation interval",ErrCorrupt)
        }
        next:=l.cursor
        next.NextUSN=r.NextUSN
        if err:=atomicWrite(filepath.Join(l.store.dir,observationCursorName),mustJSON(next));err!=nil{return err}
        l.cursor=next
    }
}

// VerifyNoWorkObservationProof can advance an interval with NO selected
// policy observation candidates. This decision binds the exact raw source
// batch, reviewed policy and every governed scope; it is not a claim that a
// missing file was successfully re-observed.
func VerifyNoWorkObservationProof(seg Segment,roots []GovernedProcessingPlan,policy ObservationPolicy)(ObservationPublicationProof,error){
    selected,err:=SelectPolicyObservations(seg,roots,policy)
    if err!=nil{return ObservationPublicationProof{},err}
    if len(selected.Requests)!=0{
        return ObservationPublicationProof{},ErrObservationPending
    }
    hash:=sha256.New()
    hash.Write([]byte(policy.Version))
    hash.Write([]byte{0})
    hash.Write([]byte(seg.SHA256))
    for _,root:=range roots{
        hash.Write([]byte{0})
        hash.Write([]byte(root.ScopeID))
        raw,_:=json.Marshal(root.RootIdentity)
        hash.Write(raw)
    }
    return ObservationPublicationProof{
        receipt:observationProofVersion+":"+hex.EncodeToString(hash.Sum(nil)),
        sourceSHA:seg.SHA256,startUSN:seg.Batch.StartUSN,nextUSN:seg.Batch.NextUSN,
    },nil
}

// BeginObservationPublication must precede the FIRST append of independently
// observed NTFS records to FI spool. On restart an unresolved intent never
// authorizes another OS re-read or duplicate spool publication.
func (l *ObservationLedger) BeginObservationPublication(seg Segment)error{
    if l==nil{return errors.New("independent NTFS observation ledger required")}
    l.mu.Lock();defer l.mu.Unlock()
    current,ok,err:=l.nextLocked()
    if err!=nil{return err}
    if !ok || current.SHA256!=seg.SHA256 || current.Batch.NextUSN!=seg.Batch.NextUSN{
        return fmt.Errorf("%w: attempted observation of foreign source",ErrConflict)
    }
    path:=filepath.Join(l.store.dir,observationIntentPrefix+seg.Name)
    if _,err:=os.Lstat(path);err==nil{return ErrAmbiguousObservation
    }else if !errors.Is(err,os.ErrNotExist){return err}
    intent:=observationReceipt{Version:SchemaVersion,
        StartUSN:seg.Batch.StartUSN,NextUSN:seg.Batch.NextUSN,
        SourceBatchSHA256:seg.SHA256}
    return atomicWrite(path,mustJSON(intent))
}

type PublishedNTFSObservation struct {
    ScopeID string
    Payload any
}

// VerifyObservationPublication inspects EXACTLY the original finalized FI
// FileObservation records, with bytes validated by spool.VerifyManifest.
// Duplicate, missing, changed, extra or unrelated records cannot move the
// independent observation cursor. The source hash is an additional local
// binding; FileObservation remains a CURRENT NTFS fact, not an event-time fact.
func VerifyObservationPublication(
    seg Segment,expected []PublishedNTFSObservation,batches []spool.FinalizedBatch,
)(ObservationPublicationProof,error){
    if len(expected)==0||len(batches)==0||seg.SHA256==""{
        return ObservationPublicationProof{},errors.New("verified independent FI observations required")
    }
    wanted:=make([][]byte,len(expected))
    for i,e:=range expected{
        if e.ScopeID==""||e.Payload==nil{
            return ObservationPublicationProof{},errors.New("observation missing governed scope or actual facts")
        }
        data,err:=json.Marshal(e.Payload)
        if err!=nil{return ObservationPublicationProof{},err}
        wanted[i]=data
    }
    seen:=map[string]struct{}{}
    count:=0
    receipts:=make([]string,0,len(batches))
    for _,batch:=range batches{
        if batch.ManifestPath==""{
            return ObservationPublicationProof{},errors.New("missing observation spool manifest")
        }
        verified,err:=spool.VerifyManifest(batch.ManifestPath)
        if err!=nil||!verified.Verified{
            return ObservationPublicationProof{},fmt.Errorf("verify observation spool: %w",err)
        }
        if verified.Manifest.BatchID!=batch.Manifest.BatchID ||
            verified.Manifest.DataSHA256!=batch.Manifest.DataSHA256 ||
            verified.DataPath!=batch.DataPath {
            return ObservationPublicationProof{},errors.New("changed observation spool metadata")
        }
        if _,exists:=seen[verified.Manifest.BatchID];exists{
            return ObservationPublicationProof{},errors.New("duplicated observation spool batch")
        }
        seen[verified.Manifest.BatchID]=struct{}{}
        file,err:=os.Open(verified.DataPath);if err!=nil{return ObservationPublicationProof{},err}
        scan:=bufio.NewScanner(file)
        scan.Buffer(make([]byte,4096),spool.DefaultMaxBatchBytes)
        batchCount:=0
        for scan.Scan(){
            var record spool.Record
            if err:=json.Unmarshal(scan.Bytes(),&record);err!=nil{
                _=file.Close();return ObservationPublicationProof{},err
            }
            if count>=len(wanted)||record.Version!=spool.RecordVersion ||
                record.RecordKind!="FileObservation" ||
                record.ScopeID!=expected[count].ScopeID ||
                !bytes.Equal(record.Payload,wanted[count]){
                _=file.Close()
                return ObservationPublicationProof{},errors.New("FI observation spool has altered, unexpected or extra source facts")
            }
            count++
            batchCount++
        }
        scanErr:=scan.Err()
        closeErr:=file.Close()
        if scanErr!=nil||closeErr!=nil{
            return ObservationPublicationProof{},fmt.Errorf("read original observation custody: %v %v",scanErr,closeErr)
        }
        if batchCount!=verified.Manifest.RecordCount{
            return ObservationPublicationProof{},errors.New("FI observation spool source count mismatch")
        }
        receipts=append(receipts,verified.Manifest.BatchID+":"+verified.Manifest.DataSHA256)
    }
    if count!=len(wanted){
        return ObservationPublicationProof{},fmt.Errorf("FI observations missing %d required records",len(wanted)-count)
    }
    sort.Strings(receipts)
    hash:=sha256.New()
    hash.Write([]byte(seg.SHA256))
    hash.Write([]byte{0})
    for _,receipt:=range receipts{
        hash.Write([]byte(receipt))
        hash.Write([]byte{0})
    }
    return ObservationPublicationProof{
        receipt:observationProofVersion+":"+hex.EncodeToString(hash.Sum(nil)),
        sourceSHA:seg.SHA256,startUSN:seg.Batch.StartUSN,
        nextUSN:seg.Batch.NextUSN,spoolPublished:true,
    },nil
}
