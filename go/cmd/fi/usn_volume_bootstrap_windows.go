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
    "strconv"
    "sync"

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
    CapturedNextUSN string `json:"captured_next_usn,omitempty"`
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
        value.Collector.USNCaptureMaxBytes==0 ||
        value.Collector.USNCaptureMinFreeBytes==0 ||
        value.Collector.USNCaptureEvery<=0 ||
        value.Collector.USNObservationEvery<=0 ||
        value.Collector.USNObservationMaxObjectsPerSegment<=0 {
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
// successful baseline is necessary yet never sufficient. The original
// journal anchor is durably initialized BEFORE baseline work, and an
// independent raw capture worker runs DURING every expensive baseline.
// Processing stays disabled until all baselines and source custody pass.
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
    // Establish one owner-only immutable capture queue BEFORE any expensive
    // baseline. Capture begins at the original PRE-baseline USN for each
    // volume. Baseline may take hours; it must NEVER stall raw journal reads.
    // If baseline or capture fails the queue is retained for forensic review.
    type captureJob struct {
        store *usncapture.Store
        owner interface{ Close() error }
    }
    jobs:=make([]captureJob,0,len(preparedGroups))
    defer func(){
        for _,job:=range jobs{_ =job.owner.Close()}
    }()
    for i,group:=range preparedGroups{
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
            return result,fmt.Errorf("create original pre-baseline USN cursor %s: %w",dir,err)
        }
        // Observation and source-processing checkpoints are independent. Both
        // start at the exact PRE-baseline NTFS journal position; never derive
        // missing observation state from a later live journal head.
        if err:=usncapture.InitializeObservationCursor(dir,cursor);err!=nil{
            return result,fmt.Errorf("initialize independent original NTFS observation cursor: %w",err)
        }
        owner,err:=usncapture.AcquireCaptureOwner(dir)
        if err!=nil{return result,fmt.Errorf("lock pre-baseline source %s: %w",dir,err)}
        jobs=append(jobs,captureJob{owner:owner})
        store,err:=usncapture.Open(dir,value.Collector.USNCaptureMaxBytes)
        if err!=nil{return result,err}
        if !reflect.DeepEqual(store.CaptureCursor(),cursor) ||
            !reflect.DeepEqual(store.ProcessingCursor(),cursor){
            return result,errors.New("pre-baseline volume source cursor failed durable readback")
        }
        if err:=store.SetFreeSpacePolicy(value.Collector.USNCaptureMinFreeBytes,
            volumeSourceAvailableFreeBytes);err!=nil{return result,err}
        jobs[len(jobs)-1].store=store
        result.Volumes[i].Initialized=true
    }

    captureCtx,stopCapture:=context.WithCancel(ctx)
    var captureWait sync.WaitGroup
    captureFailures:=make(chan error,len(preparedGroups))
    for i,group:=range preparedGroups{
        i,group:=i,group
        captureWait.Add(1)
        go func(){
            defer captureWait.Done()
            err:=runServiceUSNRawCaptureStore(captureCtx,value.Collector.USNCaptureEvery,
                group.group.CaptureScopeID,group.group.RepresentativeRoot,
                jobs[i].store,func(record serviceRuntimeRecord)error {
                    return appendServiceRuntimeRecordAt(value.Storage.StateDir,record)
                })
            if err!=nil{
                captureFailures<-fmt.Errorf("pre-baseline volume %s capture: %w",
                    group.group.CaptureScopeID,err)
                stopCapture()
            }
        }()
    }
    // Cancellation must always finish before releasing owners (including
    // failures in the baseline stage). Do not leave a detached capture
    // process running past bootstrap.
    captureStopped:=false
    stopAndJoin:=func(){
        if captureStopped{return}
        captureStopped=true
        stopCapture()
        captureWait.Wait()
    }
    defer stopAndJoin()
    checkCaptureFailure:=func()error{
        select{
        case failure:=<-captureFailures:return failure
        default:
            if !captureStopped && captureCtx.Err()!=nil && ctx.Err()==nil {
                return errors.New("FI pre-baseline source capture was canceled before acceptance")
            }
            return nil
        }
    }

    // Run every governed-root baseline while the raw journal worker is
    // independently preserving ORIGINAL source facts and capture cursor.
    // The processing cursor remains at the exact pre-baseline anchor.
    for i,group:=range preparedGroups {
        for _,root:=range group.group.GovernedRoots{
            if err:=captureCtx.Err();err!=nil{
                if failed:=checkCaptureFailure();failed!=nil{return result,failed}
                return result,err
            }
            scope:=configuredScopeID(root)
            baseline,err:=writeSpoolRoot(captureCtx,scope,root)
            if failed:=checkCaptureFailure();failed!=nil{return result,failed}
            if err!=nil{return result,fmt.Errorf("verified baseline %q: %w",root,err)}
            if err:=validateBaselineSpoolForCheckpoint(baseline);err!=nil{
                return result,fmt.Errorf("incomplete baseline %q: %w",root,err)
            }
            if baseline.SupportingSourceErrors!=0{
                return result,fmt.Errorf("FI baseline %q has %d unresolved supporting-source errors",
                    root,baseline.SupportingSourceErrors)
            }
            result.Volumes[i].VerifiedBaselines++
        }
    }
    // Finish the raw capture workers. The queue can only be activated by
    // the separately installed SCM service later, with the same immutable
    // source cursor. This bootstrap never starts sender or processing.
    stopAndJoin()
    if failed:=checkCaptureFailure();failed!=nil{return result,failed}

    // Exact root identities and journal IDs must survive the baseline.
    // Unlike the OLD checkpoint semantics, original NextUSN may now be
    // older than FirstUSN: that history is safely in our immutable queue.
    // The CURRENT durable capture cursor must still be in NTFS retention.
    for i,group:=range preparedGroups{
        for j,root:=range group.group.GovernedRoots{
            current,err:=captureBaselineAnchor(ctx,configuredScopeID(root),root)
            if err!=nil{return result,err}
            original:=group.rootAnchors[j]
            if current.GovernedRoot.ObjectIdentity!=original.GovernedRoot.ObjectIdentity ||
                !reflect.DeepEqual(current.GovernedRoot.VolumeIdentity,original.GovernedRoot.VolumeIdentity) ||
                current.JournalState.JournalID!=original.JournalState.JournalID ||
                !reflect.DeepEqual(current.JournalState.VolumeIdentity,original.JournalState.VolumeIdentity){
                return result,fmt.Errorf("%w: root or journal changed during baseline %q",
                    usncapture.ErrConflict,root)
            }
        }
        cursor:=jobs[i].store.CaptureCursor()
        processed:=jobs[i].store.ProcessingCursor()
        if processed.NextUSN!=group.anchor.JournalState.NextUSN ||
            cursor.ScopeID!=group.group.CaptureScopeID ||
            cursor.JournalID!=group.group.JournalID ||
            !reflect.DeepEqual(cursor.VolumeIdentity,group.group.VolumeIdentity){
            return result,fmt.Errorf("%w: pre-baseline source custody moved or changed identity",
                usncapture.ErrConflict)
        }
        current,err:=usn.QueryJournal(ctx,group.group.CaptureScopeID,
            group.group.RepresentativeRoot)
        if err!=nil{return result,err}
        first,err:=strconv.ParseUint(current.FirstUSN,10,64)
        if err!=nil{return result,err}
        lowest,err:=strconv.ParseUint(current.LowestValidUSN,10,64)
        if err!=nil{return result,err}
        captured,err:=strconv.ParseUint(cursor.NextUSN,10,64)
        if err!=nil{return result,err}
        if current.JournalID!=cursor.JournalID ||
            !reflect.DeepEqual(current.VolumeIdentity,cursor.VolumeIdentity){
            return result,fmt.Errorf("%w: original NTFS journal changed during bootstrap",
                usncapture.ErrConflict)
        }
        if captured<first || (lowest!=0 && captured<lowest){
            return result,fmt.Errorf("%w: journal outran durable pre-baseline capture",
                usncapture.ErrGap)
        }
        // Avoid claiming unmeasured service-start continuity. The next
        // service startup checks the same cursor against FirstUSN again.
        result.Volumes[i].CapturedNextUSN=cursor.NextUSN
    }
    // Only a fully verified multi-root bootstrap may authorize activation.
    // A failure before this final marker retains raw source custody, but the
    // FI service cannot treat an incomplete install as a completed baseline.
    witness:=volumeBootstrapWitness{Version:volumeBootstrapWitnessVersion,
        Volumes:make([]volumeBootstrapWitnessVolume,0,len(preparedGroups))}
    for _,group:=range preparedGroups {
        v:=volumeBootstrapWitnessVolume{
            CaptureScopeID:group.group.CaptureScopeID,
            JournalID:group.group.JournalID,
            VolumeIdentity:group.group.VolumeIdentity,
            OriginalNextUSN:group.anchor.JournalState.NextUSN,
            Roots:make([]volumeBootstrapRoot,0,len(group.group.GovernedRoots)),
        }
        for i,root:=range group.group.GovernedRoots {
            v.Roots=append(v.Roots,volumeBootstrapRoot{
                Path:root,ScopeID:configuredScopeID(root),
                Identity:group.rootAnchors[i].GovernedRoot.ObjectIdentity,
            })
        }
        witness.Volumes=append(witness.Volumes,v)
    }
    if err:=commitVolumeBootstrapWitness(value.Storage.USNCaptureDir,witness);err!=nil{
        return result,fmt.Errorf("persist fully accepted original FI bootstrap boundary: %w",err)
    }
    result.Status="SourceAnchorsInitialized"
    return result,nil
}
