// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import ("context";"errors";"time")

// Coverage owns audited policies, governed-root coverage, and Security gaps.
// It never empties unrelated Security or File buffers.
func(w *privateP6SQLCoordinator) coverage(ctx context.Context,
    rows []privateP6Record,ids []int64)error{
    if len(rows)!=len(ids){return errors.New("FI P6 Coverage: source IDs mismatch")}
    buffer:=newSecurityCoverageBulkState(w.profile)
    for i,r:=range rows{
        if ids[i]<=0{return errors.New("FI P6 Coverage: missing signed FK")}
        if r.prepared.Record.RecordKind=="WindowsSecurityCoverage"{
            if err:=buffer.add(ctx,w.tx,ids[i],r.prepared);err!=nil{return err}
            continue
        }
        if r.prepared.Record.RecordKind!="WindowsSecurityContinuityGap"{
            return errors.New("FI P6 Coverage: unsupported record kind")
        }
        started:=time.Now()
        err:=ProjectSourceRecord(ctx,w.tx,w.sourceID,ids[i],r.prepared)
        elapsed:=time.Since(started)
        w.profile.Projection+=elapsed
        w.profile.OtherProjection+=elapsed
        if err!=nil{return err}
    }
    return buffer.flush(ctx,w.tx)
}
