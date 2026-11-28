// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "bufio"
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
)

// processCapturedUSNVolumeOnce runs a SINGLE bounded consumer pass over an
// already durable USN volume segment. It never accesses the live NTFS journal.
// No File-ID re-observation, content hashing or current-state path filtering
// is performed in this source-only lane.
//
// WIRING GATE: this is not yet selected by FICollector -service. Durable
// publication replay/retention and historical scope-index ownership must
// be verified before integrating with service startup.
func processCapturedUSNVolumeOnce(
    ctx context.Context,
    store *usncapture.Store,
    roots []usncapture.GovernedProcessingPlan,
    spoolDir string,
    collector spool.CollectorIdentity,
) (bool,error) {
    return processCapturedUSNVolumeOnceWithHistory(ctx,store,roots,spoolDir,collector,nil)
}

func processCapturedUSNVolumeOnceWithHistory(
    ctx context.Context,
    store *usncapture.Store,
    roots []usncapture.GovernedProcessingPlan,
    spoolDir string,
    collector spool.CollectorIdentity,
    history *usncapture.DirectoryHistoryIndex,
) (bool,error) {
    if ctx == nil || store == nil || len(roots)==0 || spoolDir=="" {
        return false,errors.New("FI USN processing requires capture store, governed roots and spool")
    }
    if err:=ctx.Err();err!=nil{return false,err}
    seg,ok,err:=store.Next()
    if errors.Is(err,usncapture.ErrAmbiguousPublication){
        pending,hasIntent,readErr:=store.PendingAmbiguousPublication()
        if readErr!=nil{return false,readErr}
        if !hasIntent{return false,err}
        if history!=nil{
            if err:=history.AddSegment(pending);err!=nil{return false,err}
        }
        expected,buildErr:=usncapture.BuildVolumeProjections(pending,roots)
        if buildErr!=nil{return false,buildErr}
        published,recoverErr:=findPublishedScopedUSNBatches(ctx,spoolDir,expected)
        if recoverErr!=nil{return false,recoverErr}
        proof,proofErr:=usncapture.VerifyScopedPublication(expected,published)
        if proofErr!=nil{
            return false,fmt.Errorf("%w: published source cannot be proven: %v",
                usncapture.ErrAmbiguousPublication,proofErr)
        }
        if err:=ctx.Err();err!=nil{return false,err}
        if err:=store.CommitProcessed(pending,proof);err!=nil{return false,err}
        return true,nil
    }
    if err!=nil||!ok{return false,err}
    if history!=nil{
        if err:=history.AddSegment(seg);err!=nil{return false,err}
    }
    projections,err:=usncapture.BuildVolumeProjections(seg,roots)
    if err!=nil{return false,err}
    if err:=ctx.Err();err!=nil{return false,err}
    writer,err:=spool.NewWriter(spoolDir,spool.DefaultBatchSize,collector)
    if err!=nil{return false,err}
    // The writer has passed all preflight checks, but has published NOTHING
    // yet. Durably mark this exact source interval before its first spool
    // append, so restart cannot send it twice if publication succeeds but
    // the processed-cursor receipt is interrupted.
    if err:=store.BeginScopedPublication(seg);err!=nil{
        _ = writer.Abandon()
        return false,fmt.Errorf("begin fail-closed scoped USN publication: %w",err)
    }
    // No source cursor is touched until every governed root is written
    // to immutable FI custody and independently proven.
    for _,p:=range projections{
        if err:=ctx.Err();err!=nil{
            _ = writer.Abandon() // retain .open work without publishing partial source
            return false,err
        }
        if err:=writer.Append("USNScopedCapture",p.GovernedScopeID,p);err!=nil{
            _ = writer.Abandon()
            return false,fmt.Errorf("append scoped USN source: %w",err)
        }
    }
    if err:=writer.Close();err!=nil{return false,fmt.Errorf("finalize scoped USN custody: %w",err)}
    batches:=writer.FinalizedBatches()
    proof,err:=usncapture.VerifyScopedPublication(projections,batches)
    if err!=nil{return false,fmt.Errorf("verify scoped source custody: %w",err)}
    if err:=ctx.Err();err!=nil{return false,err}
    if err:=store.CommitProcessed(seg,proof);err!=nil{
        return false,fmt.Errorf("advance processed USN cursor only after verified spool: %w",err)
    }
    return true,nil
}

// findPublishedScopedUSNBatches is a COLD-START recovery path only. It does
// not read NTFS, re-create a sender batch or infer successful downstream
// custody. It proves the exact finalized FI spool source remains present.
// If the sender already moved the data, processing remains safely blocked
// pending durable transport/receiver-side reconciliation.
func findPublishedScopedUSNBatches(
    ctx context.Context, spoolDir string, expected []usncapture.ScopedProjection,
) ([]spool.FinalizedBatch,error) {
    if ctx==nil || spoolDir=="" || len(expected)==0 {
        return nil,errors.New("FI scoped recovery requires original source and spool")
    }
    anchor:=expected[0]
    entries,err:=os.ReadDir(spoolDir)
    if err!=nil{
        return nil,fmt.Errorf("%w: cannot inspect original FI spool: %v",
            usncapture.ErrAmbiguousPublication,err)
    }
    matches:=make([]spool.FinalizedBatch,0,1)
    for _,entry:=range entries {
        if err:=ctx.Err();err!=nil{return nil,err}
        if !strings.HasSuffix(entry.Name(),".manifest.json"){continue}
        if !entry.Type().IsRegular(){
            return nil,fmt.Errorf("%w: nonregular FI manifest %q",
                usncapture.ErrAmbiguousPublication,entry.Name())
        }
        manifestPath:=filepath.Join(spoolDir,entry.Name())
        verified,err:=spool.VerifyManifest(manifestPath)
        if err!=nil || !verified.Verified{
            return nil,fmt.Errorf("%w: invalid finalized spool %s: %v",
                usncapture.ErrAmbiguousPublication,entry.Name(),err)
        }
        file,err:=os.Open(verified.DataPath)
        if err!=nil{return nil,fmt.Errorf("%w: %v",usncapture.ErrAmbiguousPublication,err)}
        scan:=bufio.NewScanner(file)
        scan.Buffer(make([]byte,4096),spool.DefaultMaxBatchBytes)
        containsOriginal:=false
        for scan.Scan(){
            if err:=ctx.Err();err!=nil{_ =file.Close();return nil,err}
            var record spool.Record
            if err:=json.Unmarshal(scan.Bytes(),&record);err!=nil{
                _ =file.Close()
                return nil,fmt.Errorf("%w: malformed published record: %v",
                    usncapture.ErrAmbiguousPublication,err)
            }
            if record.RecordKind!="USNScopedCapture"{continue}
            var v struct{
                CaptureScopeID string `json:"capture_scope_id"`
                JournalID string `json:"journal_id"`
                StartUSN string `json:"start_usn"`
                NextUSN string `json:"next_usn"`
            }
            if err:=json.Unmarshal(record.Payload,&v);err!=nil{
                _ =file.Close()
                return nil,fmt.Errorf("%w: malformed scoped record: %v",
                    usncapture.ErrAmbiguousPublication,err)
            }
            if v.CaptureScopeID==anchor.CaptureScopeID &&
                v.JournalID==anchor.JournalID &&
                v.StartUSN==anchor.StartUSN &&
                v.NextUSN==anchor.NextUSN {
                // Do NOT filter by claimed SHA: the full independent verifier
                // must detect a changed digest, altered record or missing root.
                containsOriginal=true
            }
        }
        scanErr:=scan.Err()
        closeErr:=file.Close()
        if scanErr!=nil||closeErr!=nil {
            return nil,fmt.Errorf("%w: FI published scan failed: %v %v",
                usncapture.ErrAmbiguousPublication,scanErr,closeErr)
        }
        if containsOriginal {
            matches=append(matches,spool.FinalizedBatch{
                DataPath:verified.DataPath,ManifestPath:manifestPath,
                Manifest:verified.Manifest,
            })
        }
    }
    if len(matches)==0{
        return nil,fmt.Errorf("%w: original FI spool not locally provable; no replay authorized",
            usncapture.ErrAmbiguousPublication)
    }
    return matches,nil
}
