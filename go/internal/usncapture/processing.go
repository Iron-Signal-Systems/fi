// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "errors"
    "fmt"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

// GovernedProcessingPlan is one consumer of an already-captured NTFS volume
// stream. The same raw segment is never independently reread from Windows for
// each governed root. Historical scope proof is per-root and never shared.
type GovernedProcessingPlan struct {
    ScopeID string
    RootIdentity records.NTFSObjectIdentity
    Resolve ScopeResolver
}

// BuildVolumeProjections produces a separate source-bound projection for every
// configured root on this volume. A failure in any root prevents successful
// publication of the volume batch and advancement of its processed cursor.
// The caller must durably publish ALL outputs before CommitProcessed.
func BuildVolumeProjections(seg Segment, roots []GovernedProcessingPlan) ([]ScopedProjection,error) {
    if len(roots)==0 {
        return nil,errors.New("volume source processing requires governed roots")
    }
    scope,err:=VolumeCaptureScopeID(seg.Batch.VolumeIdentity)
    if err!=nil || scope!=seg.Batch.ScopeID {
        return nil,errors.New("source segment does not match a unique NTFS volume")
    }
    seen:=make(map[string]struct{},len(roots))
    projections:=make([]ScopedProjection,0,len(roots))
    for _,root:=range roots {
        if root.ScopeID=="" || root.Resolve==nil {
            return nil,errors.New("missing governed-root processing scope or resolver")
        }
        if _,ok:=seen[root.ScopeID];ok {
            return nil,fmt.Errorf("duplicate governed-root consumer %q",root.ScopeID)
        }
        seen[root.ScopeID]=struct{}{}
        selected,err:=SelectCapturedScope(seg.Batch,root.ScopeID,root.RootIdentity,root.Resolve)
        if err!=nil{return nil,fmt.Errorf("scope %s: %w",root.ScopeID,err)}
        projection,err:=BuildScopedProjection(seg,root.ScopeID,root.RootIdentity,selected)
        if err!=nil{return nil,fmt.Errorf("project scope %s: %w",root.ScopeID,err)}
        projections=append(projections,projection)
    }
    return projections,nil
}
