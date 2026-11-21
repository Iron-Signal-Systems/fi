//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "errors"
    "github.com/jackc/pgx/v5"
)

// Security owns the source-anchored event, scope, and field COPY.
// P6's common source ledger already inserted original source parents.
// The clone-only change to copySecurityBulk skips only duplicate parent COPY;
// audited forty-column events and child streamers remain unchanged.
func(w *privateP6SQLCoordinator) security(ctx context.Context,
    rows []privateP6Record,ids []int64)error{
    if len(rows)!=len(ids){return errors.New("FI P6 Security: source IDs mismatch")}
    // The native fi-sor SQL process uses the already-approved, frozen P4
    // Security candidate. The old disposable-clone experiment guard stays
    // unchanged for every existing benchmark/replay call.
    tune:=ctx!=nil && ctx.Value(c1NativeFrozenSecurityContextKey{})==true
    if !tune {
        selected,e:=privateC1Security8GiBExperiment()
        if e!=nil{return e}
        tune=selected
    }
    profile:="P3"
    if tune{profile="P4"}
    ctx,err:=withFixedSecurityBulkProfile(ctx,profile)
    if err!=nil{return err}
    if tune{ctx=withC1SecurityCOPYExperiment(ctx)}
    ctx=context.WithValue(ctx,privateP6SourceAlreadyInsertedKey{},true)
    pending:=make([]securityBulkRecord,len(rows))
    for i,r:=range rows{
        if r.selectedSinglePass{
            pending[i]=r.singlePassSecurity
            if pending[i].prepared.Record.RecordKind!="WindowsSecurityEvent"{
                return errors.New("FI P6 Security: invalid pre-decoded event")
            }
        }else{
            pending[i],err=prepareSecurityBulkRecord(r.ordinal,
                r.prepared,r.prepared.RecordDigest[:])
            if err!=nil{return err}
        }
        pending[i].ordinal=r.ordinal
        pending[i].prepared=r.prepared
        pending[i].digest=r.prepared.RecordDigest[:]
        pending[i].sourceBatchID=r.sourceBatchID
        pending[i].sourceRecordID=ids[i]
    }
    // The helper verifies returned SQL IDs by original (batch,ordinal).
    if err=copySecurityBulk(ctx,w.tx,pending[0].sourceBatchID,pending,w.profile);err!=nil{
        return err
    }
    for i:=range pending{
        if pending[i].sourceRecordID!=ids[i]{
            return errors.New("FI P6 Security: returned FK differs from original source")
        }
    }
    return nil
}
var _ pgx.Tx = privateProjectionTx{}
