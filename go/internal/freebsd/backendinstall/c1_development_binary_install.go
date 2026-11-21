// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Install C1 DEVELOPMENT worker executables into their separate FreeBSD jail
// roots. This never installs an rc service, replaces the existing worker,
// enables C1 SQL admission or changes any PostgreSQL table.
package backendinstall

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
)

func buildC1DevelopmentBinaryPlan(config Config,releaseDirectory string)(
    applicationBinaryPlan,error,
){
    directory,err:=requireApplicationBinaryReleaseDirectory(releaseDirectory)
    if err!=nil{return applicationBinaryPlan{},err}
    ingestRoot:=config.Value("FI_INGEST_ROOT")
    sorRoot:=config.Value("FI_SOR_DB_ROOT")
    if !filepath.IsAbs(ingestRoot)||!filepath.IsAbs(sorRoot)||
        filepath.Clean(ingestRoot)=="/"||filepath.Clean(sorRoot)=="/"||
        filepath.Clean(ingestRoot)==filepath.Clean(sorRoot){
        return applicationBinaryPlan{},errors.New("FI C1 development installer: distinct absolute existing ingest/SoR jail roots required")
    }
    for _,root:=range []string{ingestRoot,sorRoot}{
        info,e:=os.Lstat(root)
        if e!=nil{return applicationBinaryPlan{},e}
        if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{
            return applicationBinaryPlan{},errors.New("FI C1 development installer: jail root is not a real directory")
        }
    }
    ingestContent,e:=loadApplicationBinarySource(filepath.Join(directory,"fi-c1-ingest-worker"))
    if e!=nil{return applicationBinaryPlan{},fmt.Errorf("C1 ingest development executable: %w",e)}
    sorContent,e:=loadApplicationBinarySource(filepath.Join(directory,"fi-c1-sor-worker"))
    if e!=nil{return applicationBinaryPlan{},fmt.Errorf("C1 SoR development executable: %w",e)}
    schemaContent,e:=loadApplicationBinarySource(filepath.Join(directory,"fi-c1-private-schema"))
    if e!=nil{return applicationBinaryPlan{},fmt.Errorf("C1 fi-sor OFFLINE private schema installer executable: %w",e)}
    hostContent,e:=loadApplicationBinarySource(filepath.Join(directory,"fi-c1-host-preflight"))
    if e!=nil{return applicationBinaryPlan{},fmt.Errorf("C1 native host RAM preflight executable: %w",e)}
    ingestParent:=filepath.Join(ingestRoot,"usr/local/sbin")
    sorParent:=filepath.Join(sorRoot,"usr/local/sbin")
    hostParent:="/usr/local/sbin"
    return applicationBinaryPlan{
        Parents:[]lifecycleParentSpec{
            {Path:ingestParent,Mode:0755,UID:0,GID:0,Role:"c1-ingest-local-sbin"},
            {Path:sorParent,Mode:0755,UID:0,GID:0,Role:"c1-sor-local-sbin"},
            {Path:hostParent,Mode:0755,UID:0,GID:0,Role:"c1-host-local-sbin"},
        },
        Files:[]applicationBinaryFileSpec{
            {Target:filepath.Join(ingestParent,"fi-c1-ingest-worker"),
                Content:ingestContent,Mode:0555,UID:0,GID:0,Role:"c1-ingest-development"},
            {Target:filepath.Join(sorParent,"fi-c1-sor-worker"),
                Content:sorContent,Mode:0555,UID:0,GID:0,Role:"c1-sor-development"},
            {Target:filepath.Join(sorParent,"fi-c1-private-schema"),
                Content:schemaContent,Mode:0555,UID:0,GID:0,Role:"c1-sor-offline-private-schema-admin"},
            {Target:filepath.Join(hostParent,"fi-c1-host-preflight"),
                Content:hostContent,Mode:0555,UID:0,GID:0,Role:"c1-native-host-read-only-preflight"},
        },
    },nil
}

// Explicit opt-in. Existing installed executables are never overwritten;
// exact matching content/ownership/mode is the only accepted repeat apply.
func ApplyC1DevelopmentBinaries(config Config,releaseDirectory string)error{
    if err:=requireHostFileHost(config,systemHostProbe{});err!=nil{return err}
    plan,err:=buildC1DevelopmentBinaryPlan(config,releaseDirectory)
    if err!=nil{return err}
    if err=preclassifyApplicationBinaryPlan(plan);err!=nil{return err}
    for _,spec:=range plan.Parents{
        switch state:=classifyLifecycleParent(spec);state{
        case lifecycleParentDirectoryMatch:
            continue
        case lifecycleParentAbsent:
            if err=createLifecycleParent(spec);err!=nil{return err}
        default:
            return fmt.Errorf("C1 development installer: parent %s changed to %s",spec.Role,state)
        }
    }
    for _,spec:=range plan.Files{
        switch state:=classifyApplicationBinaryFile(spec);state{
        case applicationBinaryFileOwnedMatch:
            continue
        case applicationBinaryFileAbsent:
            if err=publishAbsentApplicationBinary(spec);err!=nil{return err}
        default:
            return fmt.Errorf("C1 development installer: executable %s changed to %s",spec.Role,state)
        }
    }
    return verifyApplicationBinaryPlan(plan)
}

func VerifyC1DevelopmentBinaries(config Config,releaseDirectory string)error{
    if err:=requireHostFileHost(config,systemHostProbe{});err!=nil{return err}
    plan,err:=buildC1DevelopmentBinaryPlan(config,releaseDirectory)
    if err!=nil{return err}
    return verifyApplicationBinaryPlan(plan)
}
