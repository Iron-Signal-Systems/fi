// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "context"
    "errors"
    "os"
    "path/filepath"
    "testing"
)

func TestSourceServiceFirstStartRequiresFullVerifiedBaselineAndNeverRebases(t *testing.T){
    dir:=t.TempDir()
    snapshot:=serviceOperationalSnapshot{USNMode:"volume-source-v1",USNCaptureDir:dir}
    w,_,_:=fixtureVolumeBootstrapWitness(t)
    count:=0
    apply:=func(context.Context)(freshUSNBootstrapSummary,error){
        count++
        if err:=commitVolumeBootstrapWitness(dir,w);err!=nil{return freshUSNBootstrapSummary{},err}
        return freshUSNBootstrapSummary{Status:"SourceAnchorsInitialized",
            Volumes:[]freshVolumeBootstrap{{VolumeScopeID:w.Volumes[0].CaptureScopeID}}},nil
    }
    if err:=ensureServiceUSNVolumeSourceBootstrap(context.Background(),snapshot,apply);err!=nil{
        t.Fatalf("FI gMSA service cannot produce first verified bootstrap: %v",err)
    }
    if err:=ensureServiceUSNVolumeSourceBootstrap(context.Background(),snapshot,apply);err!=nil{
        t.Fatalf("FI source restarted despite valid original custody: %v",err)
    }
    if count!=1{t.Fatalf("FI source first-start reset existing journal anchor: calls=%d",count)}
    if err:=os.WriteFile(filepath.Join(dir,volumeBootstrapWitnessFile),[]byte("{corrupt"),0600);err!=nil{t.Fatal(err)}
    if err:=ensureServiceUSNVolumeSourceBootstrap(context.Background(),snapshot,apply);err==nil{
        t.Fatal("FI service silently reinitialized a corrupted original source")
    }
    if count!=1{t.Fatal("failed preflight still launched source bootstrap")}
}
func TestSourceServiceRefusesPartialAndInterruptedFirstStart(t *testing.T){
    dir:=t.TempDir()
    snapshot:=serviceOperationalSnapshot{USNMode:"volume-source-v1",USNCaptureDir:dir}
    calls:=0
    fake:=func(context.Context)(freshUSNBootstrapSummary,error){
        calls++
        return freshUSNBootstrapSummary{Status:"SourceAnchorsInitialized",
            Volumes:[]freshVolumeBootstrap{{VolumeScopeID:"volume-incomplete"}}},nil
    }
    if err:=ensureServiceUSNVolumeSourceBootstrap(context.Background(),snapshot,fake);err==nil{
        t.Fatal("FI service activated with no durable original-source witness")
    }
    ctx,cancel:=context.WithCancel(context.Background());cancel()
    if err:=ensureServiceUSNVolumeSourceBootstrap(ctx,snapshot,fake);!errors.Is(err,context.Canceled){
        t.Fatalf("FI canceled bootstrap continued: %v",err)
    }
    if calls!=1{t.Fatal("canceled source start ran a new journal baseline")}
    if err:=os.Mkdir(filepath.Join(dir,"partial-queue"),0700);err!=nil{t.Fatal(err)}
    if err:=ensureServiceUSNVolumeSourceBootstrap(context.Background(),snapshot,
        func(ctx context.Context)(freshUSNBootstrapSummary,error){
            return initializeFreshUSNVolumeSources(ctx)
        });err==nil{
        t.Fatal("partial original capture queue was silently reset")
    }
}
