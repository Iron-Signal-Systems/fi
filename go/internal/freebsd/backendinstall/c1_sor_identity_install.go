// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// A dedicated, unprivileged FI C1 SoR service identity is needed inside
// fi-sor-db. This is separate from the existing fi-ingest identity, and
// does not grant PostgreSQL access or start any service.
package backendinstall

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
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
    return identitySpec{Root:sor,UID:uid,GID:gid,User:"fi-sor",Group:"fi-sor"},nil
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
        if err:=applyIdentityOne(systemIdentityMutator{},spec);err!=nil{return err}
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
