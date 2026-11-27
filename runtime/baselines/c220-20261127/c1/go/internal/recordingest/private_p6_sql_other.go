//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import ("context";"errors";"time")

// Other owns collector identity, directory/local principals and memberships,
// shares, ACEs and complete error projections; no facts are discarded.
func(w *privateP6SQLCoordinator) other(ctx context.Context,
    rows []privateP6Record,ids []int64)error{
    if len(rows)!=len(ids){return errors.New("FI P6 Other: source IDs mismatch")}
    for i,r:=range rows{
        if ids[i]<=0{return errors.New("FI P6 Other: missing signed source FK")}
        kind:=r.prepared.Record.RecordKind
        if kind!="CollectorIdentity"&&kind!="DirectoryPrincipalSnapshot" &&
            kind!="LocalPrincipalSnapshot"&&kind!="NTFSCollectionError" &&
            kind!="SMBShareSnapshot"&&kind!="SupportingSourceCollectionError"{
            return errors.New("FI P6 Other: unreviewed relational kind")
        }
        started:=time.Now()
        err:=ProjectSourceRecord(ctx,w.tx,w.sourceID,ids[i],r.prepared)
        elapsed:=time.Since(started)
        w.profile.Projection+=elapsed
        w.profile.OtherProjection+=elapsed
        if err!=nil{return err}
    }
    return nil
}
