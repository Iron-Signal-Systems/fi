// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// A dedicated unprivileged FI C1 SoR service identity is needed inside
// the existing fi-sor jail. C220 already has GID 4100 as fi-ingest-socket
// for local PostgreSQL socket access: NEVER create a second group at that
// GID or replace the existing socket group. Identity installation does
// not change PostgreSQL grants, socket permissions, or start a service.
package backendinstall

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strconv"
)

func c1SoRIdentitySpec(config Config)(identitySpec,error){
    uid,err:=parsePositiveDecimal("FI_RUNTIME_UID",config.Value("FI_RUNTIME_UID"))
    if err!=nil{return identitySpec{},err}
    gid,err:=parsePositiveDecimal("FI_RUNTIME_GID",config.Value("FI_RUNTIME_GID"))
    if err!=nil{return identitySpec{},err}
    sor:=config.Value("FI_SOR_DB_ROOT")
    if !filepath.IsAbs(sor)||filepath.Clean(sor)=="/"{
        return identitySpec{},errors.New("FI C1 identity: absolute fi-sor-db jail root required")
    }
    root,err:=os.Lstat(sor)
    if err!=nil{return identitySpec{},err}
    if !root.IsDir()||root.Mode()&os.ModeSymlink!=0{
        return identitySpec{},errors.New("FI C1 identity: existing real fi-sor jail root required")
    }
    // On the actual C220 fi-sor, PostgreSQL's existing socket access
    // group already owns numeric GID 4100. Reuse that EXACT named group
    // instead of attempting an invalid competing groupadd at 4100.
    groups,err:=readGroupRecords(filepath.Join(sor,"etc/group"))
    if err!=nil{return identitySpec{},fmt.Errorf("FI C1 identity: inspect SoR group database: %w",err)}
    name:="fi-sor"
    found:=0
    for _,group:=range groups{
        if group.GID==gid{
            found++
            if group.Name!="fi-ingest-socket"&&group.Name!="fi-sor"{
                return identitySpec{},errors.New("FI C1 identity: foreign numeric socket GID collision")
            }
            name=group.Name
        }
        if group.Name=="fi-sor"&&group.GID!=gid{
            return identitySpec{},errors.New("FI C1 identity: fi-sor group name already bound to another GID")
        }
    }
    if found>1{return identitySpec{},errors.New("FI C1 identity: duplicate numeric GID")}
    return identitySpec{Root:sor,UID:uid,GID:gid,User:"fi-sor",Group:name},nil
}

// For an existing local socket group, provision ONLY the new unprivileged
// user. The generic identity installer creates a group first, which would
// collide with fi-ingest-socket and could break PostgreSQL socket access.
// Strictly reject an occupied UID or existing fi-sor user before any write.
func c1AddSoRUserToExistingSocketGroup(mutator systemIdentityMutator,spec identitySpec)error{
    if spec.Group!="fi-ingest-socket"||spec.User!="fi-sor"{
        return errors.New("FI C1 identity: existing socket group path requires exact names")
    }
    users,err:=readPasswdRecords(filepath.Join(spec.Root,"etc/master.passwd"))
    if err!=nil{return err}
    groups,err:=readGroupRecords(filepath.Join(spec.Root,"etc/group"))
    if err!=nil{return err}
    groupCount:=0
    for _,g:=range groups{
        if g.GID==spec.GID||g.Name==spec.Group{
            if g.GID!=spec.GID||g.Name!=spec.Group{
                return errors.New("FI C1 identity: socket group collision")
            }
            groupCount++
        }
    }
    if groupCount!=1{return errors.New("FI C1 identity: socket group missing or duplicate")}
    for _,u:=range users{
        if u.UID==spec.UID||u.Name==spec.User{
            return errors.New("FI C1 identity: requested user name or UID already in use")
        }
    }
    return mutator.run("/usr/sbin/pw",
        "-R",spec.Root,"useradd","-n",spec.User,
        "-u",strconv.FormatUint(spec.UID,10),
        "-g",spec.Group,"-d",identityHome,
        "-s",identityShell,"-w","no")
}

// This command is an explicit OFFLINE operator action. Refuse an unexpected
// host, incorrect ZFS jail root, UID/GID drift or foreign identity collision.
func ApplyC1SoRIdentity(config Config)error{
    probe:=systemHostProbe{}
    if err:=requireIdentityHost(config,probe);err!=nil{return err}
    spec,err:=c1SoRIdentitySpec(config)
    if err!=nil{return err}
    jails:=jailRootSpecs(config)
    if len(jails)!=3||jails[2].Mountpoint!=spec.Root||
        inspectJailDatasetState(probe,jails[2])!=jailDatasetOwnedMatch{
        return errors.New("FI C1 identity: existing fi-sor-db ZFS jail root ownership unverified")
    }
    state:=inspectIdentityState(spec)
    switch state{
    case identityAbsent:
        // Only the dedicated fi-sor group may be created by the generic
        // two-object identity installer. The existing socket group is reused.
        if spec.Group!="fi-sor"{
            return errors.New("FI C1 identity: existing socket group unexpectedly absent")
        }
        if err:=applyIdentityOne(systemIdentityMutator{},spec);err!=nil{return err}
    case identityOwnedDrift:
        if spec.Group!="fi-ingest-socket"{
            return fmt.Errorf("FI C1 identity: existing fi-sor local account unsafe (%s)",state)
        }
        if err:=c1AddSoRUserToExistingSocketGroup(systemIdentityMutator{},spec);err!=nil{
            return fmt.Errorf("FI C1 identity: create service user without altering socket group: %w",err)
        }
    case identityOwnedMatch:
    default:
        return fmt.Errorf("FI C1 identity: existing fi-sor local account unsafe (%s)",state)
    }
    return VerifyC1SoRIdentity(config)
}

// An independent read-only local passwd/group check; does not mutate
// jail user identities or any PostgreSQL authentication settings.
func VerifyC1SoRIdentity(config Config)error{
    spec,err:=c1SoRIdentitySpec(config)
    if err!=nil{return err}
    if state:=inspectIdentityState(spec);state!=identityOwnedMatch{
        return fmt.Errorf("FI C1 identity: fi-sor jail user not exact (%s)",state)
    }
    return nil
}
