// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "context"
    "errors"
    "fmt"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
)

// Independent NTFS observation runs on its own scheduler and durable cursor.
// No attempt to open a file can delay raw USN capture or source-only P6
// publication. A failed, missing, moved or inaccessible object remains
// explicitly Partial; this never invents metadata or releases original USN
// custody. Durable downstream error/outcome acceptance remains a dev gate.
func runServiceIndependentNTFSObservationLoop(
    ctx context.Context,interval time.Duration,source *usncapture.Store,
    observations *usncapture.ObservationLedger,
    roots []usncapture.GovernedProcessingPlan,
    paths map[string]string,spoolDir string,collector spool.CollectorIdentity,
    policy usncapture.ObservationPolicy,volumeScopeID string,
    appendRecord serviceAppendRecordFunc,
)error{
    if ctx==nil||interval<=0||source==nil||observations==nil||
        len(roots)==0||len(paths)==0||volumeScopeID==""||appendRecord==nil{
        return errors.New("FI independent NTFS service requires governed original source and telemetry")
    }
    ticker:=time.NewTicker(interval)
    defer ticker.Stop()
    lastWarning:=time.Time{}
    for{
        if ctx.Err()!=nil{return nil}
        worked,err:=processIndependentNTFSObservationsOnce(
            ctx,source,observations,roots,paths,spoolDir,collector,policy,
            observeCurrentSelectedNTFS)
        if err!=nil{
            if ctx.Err()!=nil{return nil}
            if errors.Is(err,usncapture.ErrCorrupt)||errors.Is(err,usncapture.ErrGap){
                return fmt.Errorf("FI independent observation original source not recoverable: %w",err)
            }
            if lastWarning.IsZero()||time.Since(lastWarning)>=30*time.Second{
                report:=serviceRuntimeRecord{
                    Version:serviceRuntimeVersion,RecordKind:"USNIndependentObservation",
                    ObservedAt:serviceNow(),ScopeID:volumeScopeID,
                    Outcome:serviceOutcomePartial,Error:err.Error(),
                    CaptureNextUSN:source.CaptureCursor().NextUSN,
                    ProcessedNextUSN:observations.Cursor().NextUSN,
                }
                if logErr:=appendRecord(report);logErr!=nil{return logErr}
                lastWarning=time.Now()
            }
        }else if worked{
            // Drain one bounded segment at a time; raw capture and source
            // processing remain independently scheduled.
            continue
        }
        select{
        case <-ctx.Done():return nil
        case <-ticker.C:
        }
    }
}
