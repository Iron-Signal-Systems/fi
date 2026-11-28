// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package install

import (
    "path/filepath"
    "testing"

    "golang.org/x/sys/windows/svc/mgr"
)

func TestSourceModeInstallerStagesCollectorAndSenderWithSeparateReaderService(t *testing.T){
    identities:=DesiredFIIdentities{}
    contracts:=approval2Server2016ServiceContracts(identities,false,true)
    contract:=func(name string)approval2ServiceContract{
        for _,c:=range contracts{
            if c.Name==name{return c}
        }
        t.Fatalf("missing FI service %s",name)
        return approval2ServiceContract{}
    }
    for _,name:=range []string{"FICollector","FISender"}{
        if contract(name).StartType!=mgr.StartManual{
            t.Fatalf("%s auto-starts before original source bootstrap",name)
        }
    }
    for _,name:=range []string{"FIUSNReader","FIObjReader"}{
        if contract(name).StartType!=mgr.StartAutomatic{
            t.Fatalf("separate %s helper not available for governed bootstrap",name)
        }
    }
    legacy:=approval2Server2016ServiceContracts(identities,false)
    for _,c:=range legacy{
        if (c.Name=="FICollector"||c.Name=="FISender") &&
            c.StartType!=mgr.StartAutomatic{
            t.Fatalf("opt-in mode changed accepted legacy install %s",c.Name)
        }
    }
}
func TestSourceModeInstallerOwnsSeparateProtectedQueueRoot(t *testing.T){
    sourceRoot:=`D:\FI\capture-source`
    value:=ConfigState{
        Path:`C:\ProgramData\FI\config\fi.conf`,
        SpoolDir:`D:\FI\spool`,
        StageDir:`C:\ProgramData\FI\stage`,
        StateDir:`C:\ProgramData\FI\state`,
        USNMode:"volume-source-v1",
        USNCaptureDir:sourceRoot,
    }
    directories,err:=approval2OperationalDirectoryPaths(value,approval1PKIHandoff{})
    if err!=nil{t.Fatal(err)}
    found:=false
    for _,dir:=range directories{
        if filepath.Clean(dir)==filepath.Clean(sourceRoot){found=true}
    }
    if !found{t.Fatal("installer did not prepare protected original NTFS source queue root")}
    value.USNMode=""
    directories,err=approval2OperationalDirectoryPaths(value,approval1PKIHandoff{})
    if err!=nil{t.Fatal(err)}
    for _,dir:=range directories{
        if filepath.Clean(dir)==filepath.Clean(sourceRoot){
            t.Fatal("legacy installer mutated source-mode custody path")
        }
    }
}
