// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "context"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "reflect"

    "github.com/Iron-Signal-Systems/fi/go/internal/config"
    "github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
    "github.com/Iron-Signal-Systems/fi/go/internal/windows/usn"
)

// Bootstrap is permitted ONLY on a completely new FI source state. No legacy
// per-root checkpoint is imported, reset or interpreted as a safe volume
// anchor. The original USN NextUSN is captured BEFORE any baseline scan.
type freshVolumeBootstrap struct {
    VolumeScopeID string `json:"volume_scope_id"`
    JournalID string `json:"journal_id"`
    OriginalNextUSN string `json:"original_next_usn"`
    QueueDir string `json:"queue_dir"`
    RootCount int `json:"root_count"`
    VerifiedBaselines int `json:"verified_baselines"`
    Initialized bool `json:"initialized"`
}
type freshUSNBootstrapSummary struct {
    Status string `json:"status"`
    Version string `json:"version"`
    Volumes []freshVolumeBootstrap `json:"volumes"`
}

func preflightFreshUSNVolumeBootstrap(value config.Config) error {
    if value.VersionID!=config.Version11 ||
        value.Collector.USNMode!="volume-source-v1" ||
        value.Storage.USNCaptureDir=="" ||
        value.Collector.USNCaptureMaxBytes==0 {
        return errors.New("FI fresh volume bootstrap requires explicit volume-source-v1 authority")
    }
    root,err:=os.Lstat(value.Storage.USNCaptureDir)
    if err!=nil{return fmt.Errorf("secure installer must pre-create original USN queue root: %w",err)}
    if !root.IsDir() || root.Mode()&os.ModeSymlink!=0 {
        return errors.New("FI USN source custody requires a real secure directory")
    }
    queueEntries,err:=os.ReadDir(value.Storage.USNCaptureDir)
    if err!=nil{return err}
    if len(queueEntries)!=0{
        return errors.New("FI fresh volume source directory is not empty; never import or overwrite existing custody")
    }
    // Never declare a previous FI installation "fresh" just because its
    // collector service is stopped. Any retained per-root USN state is a NO GO.
    for _,root:=range value.GovernedRoots {
        scope:=configuredScopeID(root)
        candidates:=[]string{
            filepath.Join(value.Storage.StateDir,scope+"-usn.json"),
        }
        for _,file:=range candidates {
            if _,err:=os.Lstat(file);err==nil{
                return fmt.Errorf("FI legacy USN checkpoint exists at %q; fresh bootstrap refused",file)
            }else if !errors.Is(err,os.ErrNotExist){return err}
        }
    }
    // The sender must not race a fresh baseline. No preexisting finalized
    // batch, interrupted collector file or alternate FI source is imported.
    entries,err:=os.ReadDir(value.Storage.SpoolDir)
    if err==nil{
        if len(entries)!=0{
            return errors.New("FI sender spool is not empty; fresh volume bootstrap refused")
        }
    }else if !errors.Is(err,os.ErrNotExist){return err}
    return nil
}

// initializeFreshUSNVolumeSources uses existing governed baseline collection,
// but does NOT run or create the old root-owned USN catch-up checkpoint. A
// successful baseline is necessary yet never sufficient: the exact PRE-
// baseline journal anchor must still exist after ALL roots finish. No queue
// is created until every independent root/volume continuity check passes.
func initializeFreshUSNVolumeSources(ctx context.Context)(freshUSNBootstrapSummary,error){
    result:=freshUSNBootstrapSummary{Status:"Rejected",Version:"fi-usn-volume-bootstrap/1",
        Volumes:[]freshVolumeBootstrap{}}
    if ctx==nil{return result,errors.New("FI bootstrap context required")}
    value,_,err:=config.LoadDefault()
    if err!=nil{return result,err}
    if err:=preflightFreshUSNVolumeBootstrap(value);err!=nil{return result,err}
    if err:=applyConfiguredSpoolPolicy(value);err!=nil{return result,err}
    groups,err:=resolveServiceUSNVolumeCaptures(ctx,value.GovernedRoots,usn.QueryJournal)
    if err!=nil{return result,err}
    type prepared struct {
        group serviceUSNVolumeCapture
        anchor baselineAnchor
        rootAnchors []baselineAnchor
    }
    preparedGroups:=make([]prepared,0,len(groups))
    // Establish ALL starting points before beginning the first expensive
    // recursive baseline, and retain each governed root's exact identity.
    for _,group:=range groups {
        anchors:=make([]baselineAnchor,0,len(group.GovernedRoots))
        for _,root:=range group.GovernedRoots {
            anchor,err:=captureBaselineAnchor(ctx,configuredScopeID(root),root)
            if err!=nil{return result,fmt.Errorf("pre-baseline original anchor %q: %w",root,err)}
            if anchor.JournalState.JournalID!=group.JournalID ||
                !reflect.DeepEqual(anchor.JournalState.VolumeIdentity,group.VolumeIdentity){
                return result,fmt.Errorf("%w: volume changed while preparing source baseline",usncapture.ErrConflict)
            }
            anchors=append(anchors,anchor)
        }
        entry:=freshVolumeBootstrap{
            VolumeScopeID:group.CaptureScopeID,JournalID:group.JournalID,
            OriginalNextUSN:anchors[0].JournalState.NextUSN,
            QueueDir:filepath.Join(value.Storage.USNCaptureDir,group.CaptureScopeID),
            RootCount:len(anchors),
        }
        result.Volumes=append(result.Volumes,entry)
        preparedGroups=append(preparedGroups,prepared{
            group:group,anchor:anchors[0],rootAnchors:anchors,
        })
    }
    // Run verified baseline collection for EVERY root, never the legacy
    // checkpoint writer. No source queue moves during this stage.
    for i,group:=range preparedGroups {
        for _,root:=range group.group.GovernedRoots {
            if err:=ctx.Err();err!=nil{return result,err}
            scope:=configuredScopeID(root)
            baseline,err:=writeSpoolRoot(ctx,scope,root)
            if err!=nil{return result,fmt.Errorf("verified baseline %q: %w",root,err)}
            if err:=validateBaselineSpoolForCheckpoint(baseline);err!=nil{
                return result,fmt.Errorf("incomplete baseline %q: %w",root,err)
            }
            if baseline.SupportingSourceErrors!=0 {
                return result,fmt.Errorf("FI baseline %q has %d unresolved supporting-source errors",
                    root,baseline.SupportingSourceErrors)
            }
            result.Volumes[i].VerifiedBaselines++
        }
    }
    // Validate BOTH volume and per-root original anchors after all baselines.
    // A journal wrap, root move, recreated journal or identity reuse is a
    // failure, never permission to advance to today's live journal head.
    for _,group:=range preparedGroups {
        for i,root:=range group.group.GovernedRoots {
            _,_,err:=prepareCheckpointFromBaselineAnchor(ctx,
                configuredScopeID(root),root,group.rootAnchors[i])
            if err!=nil{return result,fmt.Errorf("original root USN continuity %q: %w",root,err)}
        }
        _,_,err:=prepareCheckpointFromBaselineAnchor(ctx,
            configuredScopeID(group.group.RepresentativeRoot),
            group.group.RepresentativeRoot,group.anchor)
        if err!=nil{
            return result,fmt.Errorf("original volume pre-baseline journal continuity: %w",err)
        }
    }
    // Two-phase preflight has passed. The only permitted new mutable objects
    // are one independently captured cursor pair per previously FI-free
    // volume. No previous queue/checkpoint is overwritten.
    for i,group:=range preparedGroups {
        a:=group.anchor
        cursor:=usncapture.Cursor{
            Version:usncapture.SchemaVersion,
            ScopeID:group.group.CaptureScopeID,
            JournalID:a.JournalState.JournalID,
            VolumeIdentity:a.JournalState.VolumeIdentity,
            NextUSN:a.JournalState.NextUSN,
        }
        dir:=result.Volumes[i].QueueDir
        if err:=usncapture.Initialize(dir,cursor);err!=nil{
            return result,fmt.Errorf("create fresh volume source cursor %s: %w",dir,err)
        }
        reopened,err:=usncapture.Open(dir,value.Collector.USNCaptureMaxBytes)
        if err!=nil{return result,err}
        if !reflect.DeepEqual(reopened.CaptureCursor(),cursor)||
            !reflect.DeepEqual(reopened.ProcessingCursor(),cursor){
            return result,errors.New("FI initialized volume source anchors did not survive durable readback")
        }
        result.Volumes[i].Initialized=true
    }
    result.Status="SourceAnchorsInitialized"
    return result,nil
}
