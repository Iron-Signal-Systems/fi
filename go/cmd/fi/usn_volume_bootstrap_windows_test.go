// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "os"
    "path/filepath"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/config"
)

func TestFreshVolumeBootstrapRejectsNonFreshOrExistingSourceCustody(t *testing.T){
    dir:=t.TempDir()
    queue:=filepath.Join(dir,"volume")
    spoolDir:=filepath.Join(dir,"spool")
    stateDir:=filepath.Join(dir,"state")
    if err:=os.Mkdir(queue,0700);err!=nil{t.Fatal(err)}
    if err:=os.Mkdir(spoolDir,0700);err!=nil{t.Fatal(err)}
    if err:=os.Mkdir(stateDir,0700);err!=nil{t.Fatal(err)}
    root:=`G:\FI-Test`
    value:=config.Config{
        VersionID:config.Version11,
        GovernedRoots:[]string{root},
        Collector:config.CollectorSettings{
            USNMode:"volume-source-v1",USNCaptureMaxBytes:16*1024*1024*1024,
        },
        Storage:config.StorageSettings{
            USNCaptureDir:queue,SpoolDir:spoolDir,StateDir:stateDir,
        },
    }
    if err:=preflightFreshUSNVolumeBootstrap(value);err!=nil{
        t.Fatalf("completely FI-free volume custody was rejected: %v",err)
    }
    value.Collector.USNMode="legacy"
    if err:=preflightFreshUSNVolumeBootstrap(value);err==nil{
        t.Fatal("unauthorized legacy collector could initialize new source custody")
    }
    value.Collector.USNMode="volume-source-v1"
    checkpoint:=filepath.Join(stateDir,configuredScopeID(root)+"-usn.json")
    if err:=os.WriteFile(checkpoint,[]byte("old FI checkpoint"),0600);err!=nil{t.Fatal(err)}
    if err:=preflightFreshUSNVolumeBootstrap(value);err==nil{
        t.Fatal("existing FI root checkpoint allowed fresh source baseline reset")
    }
    if err:=os.Remove(checkpoint);err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(filepath.Join(queue,"retained-source.json"),[]byte("old source"),0600);err!=nil{t.Fatal(err)}
    if err:=preflightFreshUSNVolumeBootstrap(value);err==nil{
        t.Fatal("retained source custody was overwritten by fresh bootstrap")
    }
    if err:=os.Remove(filepath.Join(queue,"retained-source.json"));err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(filepath.Join(spoolDir,"old-sender.manifest.json"),[]byte("old spool"),0600);err!=nil{t.Fatal(err)}
    if err:=preflightFreshUSNVolumeBootstrap(value);err==nil{
        t.Fatal("nonempty FI sender spool allowed unsafe fresh initialization")
    }
}
