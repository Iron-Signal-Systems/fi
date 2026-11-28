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
    "reflect"
    "sort"
    "strings"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

// ScopedPublicationProof is a capability produced only by full FI spool
// verification. Other packages cannot construct a nonzero valid proof string
// directly; CommitProcessed refuses the zero value. It is not a claim of
// downstream C220 acceptance, only local durable publication.
type ScopedPublicationProof struct {
	receipt           string
	captureScopeID     string
	journalID          string
	sourceBatchSHA256  string
	startUSN           string
	nextUSN            string
}

// Receipt is the immutable publication witness persisted in the source queue.
func (p ScopedPublicationProof) Receipt() string { return p.receipt }

// VerifyScopedPublication independently inspects immutable FI spool
// publications and proves that exactly one original source-bound projection
// for EACH governed root was published and checked. No processed cursor may
// advance before this returns. It does not claim that C220 has accepted it.
func VerifyScopedPublication(expected []ScopedProjection, batches []spool.FinalizedBatch) (ScopedPublicationProof,error) {
    if len(expected)==0 || len(batches)==0{
        return ScopedPublicationProof{},errors.New("scoped source publication requires governed projections and verified FI batches")
    }
    // A publication is exactly ONE captured volume/journal/USN interval
    // potentially fan-out to several governed roots. Mixing unrelated source
    // intervals would create a witness that could advance the wrong cursor.
    anchor:=expected[0]
    if anchor.CaptureScopeID=="" || anchor.JournalID=="" ||
        anchor.SourceBatchSHA256=="" || anchor.StartUSN=="" || anchor.NextUSN=="" {
        return ScopedPublicationProof{},errors.New("scoped publication missing original source identity")
    }
    want:=make(map[string]ScopedProjection,len(expected))
    for _,p:=range expected{
        if p.GovernedScopeID=="" || p.Version!=ScopedProjectionVersion{
            return ScopedPublicationProof{},errors.New("invalid expected USN source projection")
        }
        if p.CaptureScopeID!=anchor.CaptureScopeID ||
            p.JournalID!=anchor.JournalID ||
            p.SourceBatchSHA256!=anchor.SourceBatchSHA256 ||
            p.StartUSN!=anchor.StartUSN || p.NextUSN!=anchor.NextUSN ||
            p.VolumeIdentity!=anchor.VolumeIdentity {
            return ScopedPublicationProof{},errors.New("mixed original USN source intervals in one FI publication")
        }
        if _,ok:=want[p.GovernedScopeID];ok{return ScopedPublicationProof{},errors.New("duplicate expected governed source")}
        want[p.GovernedScopeID]=p
    }
    got:=make(map[string]bool,len(expected))
    receipts:=make([]string,0,len(batches))
    for _,batch:=range batches{
        if batch.ManifestPath==""{
            return ScopedPublicationProof{},errors.New("missing finalized FI batch manifest path")
        }
        verified,err:=spool.VerifyManifest(batch.ManifestPath)
        if err!=nil||!verified.Verified{return ScopedPublicationProof{},fmt.Errorf("verify FI manifest %s: %w",batch.ManifestPath,err)}
        if batch.Manifest.BatchID!=verified.Manifest.BatchID ||
            batch.Manifest.DataSHA256!=verified.Manifest.DataSHA256 ||
            batch.DataPath!=verified.DataPath{
            return ScopedPublicationProof{},errors.New("published FI batch metadata changed")
        }
        file,err:=os.Open(verified.DataPath)
        if err!=nil{return ScopedPublicationProof{},err}
        hash:=sha256.New()
        reader:=bufio.NewReader(io.TeeReader(file,hash))
        count:=0
        for{
            line,readErr:=reader.ReadBytes('\n')
            if len(line)>0{
                if line[len(line)-1]!='\n'{
                    file.Close()
                    return ScopedPublicationProof{},errors.New("spool source record missing final newline")
                }
                var record spool.Record
                decoder:=json.NewDecoder(bytes.NewReader(line[:len(line)-1]))
                decoder.DisallowUnknownFields()
                if err:=decoder.Decode(&record);err!=nil{file.Close();return ScopedPublicationProof{},err}
                var extra any
                if err:=decoder.Decode(&extra);err!=io.EOF{file.Close();return ScopedPublicationProof{},errors.New("trailing JSON in FI spool record")}
                count++
                if record.RecordKind!="USNScopedCapture"{continue}
                if record.Version!=spool.RecordVersion {
                    file.Close();return ScopedPublicationProof{},errors.New("invalid USN spool version")
                }
                var current ScopedProjection
                decoder=json.NewDecoder(bytes.NewReader(record.Payload))
                decoder.DisallowUnknownFields()
                if err:=decoder.Decode(&current);err!=nil{file.Close();return ScopedPublicationProof{},err}
                if err:=decoder.Decode(&extra);err!=io.EOF{file.Close();return ScopedPublicationProof{},errors.New("trailing scoped source JSON")}
                expectedProjection,ok:=want[record.ScopeID]
                if !ok||got[record.ScopeID]||current.GovernedScopeID!=record.ScopeID||
                    !reflect.DeepEqual(current,expectedProjection){
                    file.Close();return ScopedPublicationProof{},fmt.Errorf("unrecognized, duplicate or altered FI scoped source %q",record.ScopeID)
                }
                got[record.ScopeID]=true
            }
            if readErr==io.EOF{break}
            if readErr!=nil{file.Close();return ScopedPublicationProof{},readErr}
        }
        if err:=file.Close();err!=nil{return ScopedPublicationProof{},err}
        if hex.EncodeToString(hash.Sum(nil))!=verified.Manifest.DataSHA256 ||
            count!=verified.Manifest.RecordCount{
            return ScopedPublicationProof{},errors.New("FI spool source changed during verification")
        }
        receipts=append(receipts,verified.Manifest.BatchID+":"+verified.Manifest.DataSHA256)
    }
    if len(got)!=len(want){
        return ScopedPublicationProof{},fmt.Errorf("verified source publication covers %d of %d governed roots",len(got),len(want))
    }
    sort.Strings(receipts)
    digest:=sha256.Sum256([]byte(strings.Join(receipts,"\n")))
    return ScopedPublicationProof{
        receipt:"verified-fi-usn-scoped-spool/1:"+hex.EncodeToString(digest[:]),
        captureScopeID:anchor.CaptureScopeID,journalID:anchor.JournalID,
        sourceBatchSHA256:anchor.SourceBatchSHA256,
        startUSN:anchor.StartUSN,nextUSN:anchor.NextUSN,
    },nil
}
