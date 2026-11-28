// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "context"
    "errors"
    "fmt"
    "io"
    "path/filepath"
    "reflect"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/Iron-Signal-Systems/fi/go/internal/runtimeidentity"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
    "github.com/Iron-Signal-Systems/fi/go/internal/windows/ntfs"
    "github.com/Iron-Signal-Systems/fi/go/internal/windows/usn"
)

// A single exclusive owner and in-process Store mutex protect BOTH independent
// workers for an NTFS volume. Root-specific plans only process the captured
// stream and never obtain additional journal reader cursors.
type serviceUSNSourceBundle struct {
    group serviceUSNVolumeCapture
    owner io.Closer
    store *usncapture.Store
    roots []usncapture.GovernedProcessingPlan
}

func runServiceUSNVolumeSourceLoop(
    ctx context.Context,snapshot serviceOperationalSnapshot,
    appendRecord serviceAppendRecordFunc,
) error {
    if ctx==nil || appendRecord==nil || snapshot.USNMode!="volume-source-v1" ||
        snapshot.USNCaptureDir=="" || snapshot.USNCaptureMaxBytes==0 ||
        snapshot.USNProcessingEvery<=0 || snapshot.USNInterval<=0 {
        return errors.New("FI volume source service requires explicit and complete configuration")
    }
    groups,err:=resolveServiceUSNVolumeCaptures(ctx,snapshot.GovernedRoots,usn.QueryJournal)
    if err!=nil{return fmt.Errorf("discover original NTFS volume source ownership: %w",err)}
    // A partially initialized fresh source, even with two readable cursors,
    // MUST NOT activate service workers until every baseline has completed.
    if _,err:=loadVolumeBootstrapWitness(snapshot.USNCaptureDir);err!=nil{return err}
    spoolDir,err:=spool.DefaultDir()
    if err!=nil{return err}
    executable,err:=runtimeidentity.CurrentExecutable()
    if err!=nil{return err}
    collector:=spool.CollectorIdentity{
        ExecutablePath:executable.Path,ExecutableSHA256:executable.SHA256,
    }
    bundles:=make([]serviceUSNSourceBundle,0,len(groups))
    currentRoots:=make(map[string]records.NTFSObjectIdentity,len(snapshot.GovernedRoots))
    defer func(){
        for _,bundle:=range bundles{_ =bundle.owner.Close()}
    }()
    // Perform every identity/custody preflight BEFORE starting ANY source
    // worker. A missing queue is not initialized or rebased by the service.
    for _,group:=range groups {
        queueDir:=filepath.Join(snapshot.USNCaptureDir,group.CaptureScopeID)
        owner,err:=usncapture.AcquireCaptureOwner(queueDir)
        if err!=nil{return fmt.Errorf("acquire %s volume source owner: %w",group.CaptureScopeID,err)}
        bundles=append(bundles,serviceUSNSourceBundle{group:group,owner:owner})
        item:=&bundles[len(bundles)-1]
        store,err:=usncapture.Open(queueDir,snapshot.USNCaptureMaxBytes)
        if err!=nil{return fmt.Errorf("open pre-established %s source anchor: %w",group.CaptureScopeID,err)}
        cursor:=store.CaptureCursor()
        if cursor.ScopeID!=group.CaptureScopeID || cursor.JournalID!=group.JournalID ||
            !reflect.DeepEqual(cursor.VolumeIdentity,group.VolumeIdentity){
            return fmt.Errorf("%w: volume source/journal changed since its verified baseline",
                usncapture.ErrConflict)
        }
        item.store=store
        plans:=make([]usncapture.GovernedProcessingPlan,0,len(group.GovernedRoots))
        for _,root:=range group.GovernedRoots{
            scope:=configuredScopeID(root)
            observation,err:=ntfs.CollectPath(ctx,scope,root,root)
            if err!=nil{return fmt.Errorf("resolve actual NTFS root identity %q: %w",root,err)}
            if !reflect.DeepEqual(observation.GovernedRoot.VolumeIdentity,group.VolumeIdentity){
                return fmt.Errorf("%w: governed root %q changed NTFS volume",usncapture.ErrConflict,root)
            }
            rootID:=observation.GovernedRoot.ObjectIdentity
            currentRoots[root]=rootID
            plans=append(plans,usncapture.GovernedProcessingPlan{
                ScopeID:scope,RootIdentity:rootID,
                Resolve:usncapture.DirectRootScopeResolver(scope,group.JournalID,rootID),
            })
        }
        item.roots=plans
    }
    if err:=verifyVolumeBootstrapServiceAuthority(
        snapshot.USNCaptureDir,groups,currentRoots);err!=nil{return err}

    workers,stop:=context.WithCancel(ctx)
    defer stop()
    count:=len(bundles)*2
    if count==0{return errors.New("volume source service requires governed volumes")}
    done:=make(chan error,count)
    for _,bundle:=range bundles{
        item:=bundle
        go func(){
            done<-runServiceUSNRawCaptureStore(workers,snapshot.USNInterval,
                item.group.CaptureScopeID,item.group.RepresentativeRoot,
                item.store,appendRecord)
        }()
        go func(){
            done<-runServiceUSNSourceProcessingLoop(workers,snapshot.USNProcessingEvery,
                item.store,item.roots,spoolDir,collector,item.group.CaptureScopeID,
                appendRecord)
        }()
    }
    var failures error
    for n:=0;n<count;n++ {
        failure:=<-done
        if failure!=nil{
            failures=errors.Join(failures,failure)
            stop()
        }
    }
    return failures
}

// The processing lane NEVER reads the live NTFS journal and never affects the
// independent fast capture cursor. An ambiguous prior publication remains
// held for evidence reconciliation while source capture continues, bounded by
// its independent immutable queue capacity.
func runServiceUSNSourceProcessingLoop(
    ctx context.Context,interval time.Duration,store *usncapture.Store,
    roots []usncapture.GovernedProcessingPlan,spoolDir string,
    collector spool.CollectorIdentity,volumeScopeID string,
    appendRecord serviceAppendRecordFunc,
) error {
    if ctx==nil||store==nil||interval<=0||len(roots)==0||
        spoolDir==""||volumeScopeID==""||appendRecord==nil{
        return errors.New("FI scoped processing worker requires independent source and custody")
    }
    ticker:=time.NewTicker(interval)
    defer ticker.Stop()
    lastWarning:=time.Time{}
    for{
        if err:=ctx.Err();err!=nil{return nil}
        worked,err:=processCapturedUSNVolumeOnce(ctx,store,roots,spoolDir,collector)
        if err!=nil {
            if ctx.Err()!=nil{return nil}
            // Source corruption or a missing segment is not a recoverable
            // processing delay. The service fails closed, never rebases.
            if errors.Is(err,usncapture.ErrCorrupt)||
                errors.Is(err,usncapture.ErrGap){
                return err
            }
            now:=time.Now()
            if lastWarning.IsZero()||now.Sub(lastWarning)>=30*time.Second{
                report:=serviceRuntimeRecord{
                    Version:serviceRuntimeVersion,RecordKind:"USNScopedProcessing",
                    ObservedAt:serviceNow(),ScopeID:volumeScopeID,
                    Outcome:serviceOutcomePartial,Error:err.Error(),
                    CaptureNextUSN:store.CaptureCursor().NextUSN,
                    ProcessedNextUSN:store.ProcessingCursor().NextUSN,
                }
                if recordErr:=appendRecord(report);recordErr!=nil{return recordErr}
                lastWarning=now
            }
        }else if worked{
            // Drain bounded source segments without introducing artificial
            // idle waits. Capture uses its own independent goroutine.
            continue
        }
        select{
        case <-ctx.Done():return nil
        case <-ticker.C:
        }
    }
}
