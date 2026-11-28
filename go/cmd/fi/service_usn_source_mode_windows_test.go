// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "context"
    "errors"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

func testSourceServiceCollector() spool.CollectorIdentity {
    return spool.CollectorIdentity{ExecutablePath:"FICollector-test",
        ExecutableSHA256:strings.Repeat("a",64)}
}

// This is the actual service processing scheduler, NOT a second fake handler.
// No NTFS journal broker is invoked by this worker.
func TestVolumeSourceServiceProcessingDrainsDurableCapturedSegment(t *testing.T){
    store,roots:=testVolumeCaptureForProcessing(t)
    dir:=filepath.Join(t.TempDir(),"spool")
    ctx,cancel:=context.WithCancel(context.Background())
    done:=make(chan error,1)
    go func(){
        done<-runServiceUSNSourceProcessingLoop(ctx,5*time.Millisecond,store,roots,dir,
            testSourceServiceCollector(),store.CaptureCursor().ScopeID,
            func(serviceRuntimeRecord)error{return nil})
    }()
    deadline:=time.NewTimer(6*time.Second)
    defer deadline.Stop()
    for store.ProcessingCursor().NextUSN!="150"{
        select{
        case err:=<-done:
            cancel()
            t.Fatalf("real FI source processing worker stopped before source publication: %v",err)
        case <-deadline.C:
            cancel()
            t.Fatal("FI independent source processing worker did not drain captured segment")
        case <-time.After(5*time.Millisecond):
        }
    }
    cancel()
    select{
    case err:=<-done:
        if err!=nil{t.Fatalf("graceful worker shutdown failed: %v",err)}
    case <-time.After(4*time.Second):t.Fatal("source processing worker did not stop")
    }
}

// An unprovable prior publication must not kill or rebase the raw volume
// capture cursor. Capture remains independent until the bounded queue fills.
func TestVolumeSourceServiceProcessingAmbiguityDoesNotStopRawCapture(t *testing.T){
    store,roots:=testVolumeCaptureForProcessing(t)
    seg,ok,err:=store.Next()
    if err!=nil||!ok{t.Fatal("missing raw journal interval",err)}
    if err:=store.BeginScopedPublication(seg);err!=nil{t.Fatal(err)}
    ctx,cancel:=context.WithCancel(context.Background())
    done:=make(chan error,1)
    warned:=make(chan serviceRuntimeRecord,1)
    dir:=filepath.Join(t.TempDir(),"spool")
    go func(){
        done<-runServiceUSNSourceProcessingLoop(ctx,5*time.Millisecond,store,roots,dir,
            testSourceServiceCollector(),store.CaptureCursor().ScopeID,
            func(r serviceRuntimeRecord)error{select{case warned<-r:default:};return nil})
    }()
    select{
    case warning:=<-warned:
        if warning.Outcome!=serviceOutcomePartial ||
            warning.RecordKind!="USNScopedProcessing"{
            cancel();t.Fatalf("ambiguous custody was not reported as partial: %+v",warning)
        }
    case err:=<-done:
        cancel();t.Fatalf("ambiguous FI source stopped independent worker: %v",err)
    case <-time.After(5*time.Second):
        cancel();t.Fatal("ambiguous FI publication was not reported")
    }
    next:=seg.Batch
    next.StartUSN="150"
    next.NextUSN="200"
    next.Records[0].USN="154"
    next.Records[0].FileIdentity.FileReferenceNumber="7"
    if err:=store.Append(next);err!=nil{
        cancel();t.Fatalf("processing ambiguity stopped independent raw capture: %v",err)
    }
    if store.CaptureCursor().NextUSN!="200" ||
        store.ProcessingCursor().NextUSN!="100"{
        cancel();t.Fatal("independent raw capture or processed cursor lost custody")
    }
    cancel()
    select{
    case err:=<-done:
        if err!=nil{t.Fatalf("graceful ambiguous worker shutdown: %v",err)}
    case <-time.After(4*time.Second):t.Fatal("source processing did not stop")
    }
}
func TestSourceServiceRefusesImplicitActivation(t *testing.T){
    err:=runServiceUSNVolumeSourceLoop(context.Background(),
        serviceOperationalSnapshot{USNMode:"legacy"},
        func(serviceRuntimeRecord)error{return nil})
    if err==nil{t.Fatal("legacy FI was allowed to start the new source worker")}
    err=runServiceUSNVolumeSourceLoop(context.Background(),
        serviceOperationalSnapshot{USNMode:"volume-source-v1"},
        func(serviceRuntimeRecord)error{return nil})
    if err==nil||errors.Is(err,context.Canceled){
        t.Fatalf("incomplete source owner/capacity preflight did not fail: %v",err)
    }
}
