// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// P11 private C220 clone: five independent SQL modules, one per original P6
// record family. Each module is bound to exactly one PostgreSQL family lane,
// reuses its original P6 projector and COPY implementations, and shares only
// the canonical signed source-record identity lookup. No central SQL switch,
// additional source staging, window-boundary flush, or database role changes.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "time"
)

type privateP11FamilyModule struct {
    family privateP6Family
    project func(*privateP6SQLCoordinator, context.Context,
        []privateP6Record, []int64) error
}

var privateP11SQLModules = [privateP6FamilyCount]privateP11FamilyModule{
    {privateP6Security, (*privateP6SQLCoordinator).security},
    {privateP6File, (*privateP6SQLCoordinator).ntfs},
    {privateP6Coverage, (*privateP6SQLCoordinator).coverage},
    {privateP6USN, (*privateP6SQLCoordinator).usn},
    {privateP6Other, (*privateP6SQLCoordinator).other},
}

// Exactly one bounded handoff goes into the lane's own P6 SQL module.
// Parents are looked up by original signed source batch plus ordinal, and
// every row is validated against the module's declared family before SQL.
func (module privateP11FamilyModule) execute(w *privateP6SQLCoordinator,
    ctx context.Context,rows []privateP6Record,
)(time.Duration,time.Duration,error){
    if ctx==nil||w==nil||len(rows)==0||module.family>=privateP6FamilyCount||
        module.project==nil{
        return 0,0,errors.New("FI P11: incomplete typed SQL module input")
    }
    for i,r:=range rows {
        kind,err:=privateP6KindFamily(r.prepared.Record.RecordKind)
        if err!=nil||!r.valid()||kind!=module.family{
            return 0,0,fmt.Errorf("FI P11: %s module rejected signed row %d",
                privateP6FamilyNames[module.family],i)
        }
    }
    started:=time.Now()
    ids,err:=w.sourceIDs(ctx,rows)
    lookup:=time.Since(started)
    if err!=nil{return lookup,0,fmt.Errorf("FI P11: %s source FK lookup: %w",
        privateP6FamilyNames[module.family],err)}
    started=time.Now()
    err=module.project(w,ctx,rows,ids)
    elapsed:=time.Since(started)
    if err!=nil{return lookup,elapsed,fmt.Errorf("FI P11: %s original P6 SQL module: %w",
        privateP6FamilyNames[module.family],err)}
    return lookup,elapsed,nil
}
