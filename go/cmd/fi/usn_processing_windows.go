// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "context"
    "errors"
    "fmt"

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
    if ctx == nil || store == nil || len(roots)==0 || spoolDir=="" {
        return false,errors.New("FI USN processing requires capture store, governed roots and spool")
    }
    if err:=ctx.Err();err!=nil{return false,err}
    seg,ok,err:=store.Next()
    if err!=nil||!ok{return false,err}
    projections,err:=usncapture.BuildVolumeProjections(seg,roots)
    if err!=nil{return false,err}
    if err:=ctx.Err();err!=nil{return false,err}
    writer,err:=spool.NewWriter(spoolDir,spool.DefaultBatchSize,collector)
    if err!=nil{return false,err}
    // No source cursor is touched until every governed root is written
    // to immutable FI custody and independently proven.
    for _,p:=range projections{
        if err:=ctx.Err();err!=nil{
            _=writer.Close() // preserves incomplete work for forensic review
            return false,err
        }
        if err:=writer.Append("USNScopedCapture",p.GovernedScopeID,p);err!=nil{
            _=writer.Close()
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
