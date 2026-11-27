//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import ("context";"errors";"time")

// USN is strictly ordered, never generic unordered parallel SQL COPY.
// Existing capture-state validation, preceding-boundary and nested identity
// checks remain the source of truth.
func(w *privateP6SQLCoordinator) usn(ctx context.Context,
    rows []privateP6Record,ids []int64)error{
    if len(rows)!=len(ids){return errors.New("FI P6 USN: source IDs mismatch")}
    for i,r:=range rows{
        if ids[i]<=0{return errors.New("FI P6 USN: missing signed source FK")}
        if r.prepared.Record.RecordKind!="USNReadBoundary" &&
            r.prepared.Record.RecordKind!="USNObjectObservation" &&
            r.prepared.Record.RecordKind!="USNContinuityGap"{
            return errors.New("FI P6 USN: unreviewed dependent kind")
        }
        rowCtx:=ctx
        if r.prepared.Record.RecordKind=="USNObjectObservation"{
            rowCtx=context.WithValue(ctx,fileObservationBulkBytesContextKey{},
                r.prepared.RecordBytes)
        }
        started:=time.Now()
        err:=ProjectSourceRecord(rowCtx,w.tx,w.sourceID,ids[i],r.prepared)
        elapsed:=time.Since(started)
        w.profile.Projection+=elapsed
        w.profile.OtherProjection+=elapsed
        if err!=nil{return err}
    }
    return nil
}
