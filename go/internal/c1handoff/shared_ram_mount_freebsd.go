//go:build freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Deployment workers refuse to accidentally put sensitive prepared records
// onto a durable ZFS/UFS directory, or to give fi-sor a writable RAM mount.
package c1handoff

import (
    "errors"
    "fmt"
    "syscall"
)

func RequireFreeBSDRAMMount(store *RAMStore,reader bool)error{
    if store==nil||store.root==""{
        return errors.New("C1 RAM: shared host tmpfs jail mount required")
    }
    var stat syscall.Statfs_t
    if err:=syscall.Statfs(store.root,&stat);err!=nil{
        return fmt.Errorf("C1 RAM: inspect live FreeBSD RAM mount: %w",err)
    }
    name:=make([]byte,0,len(stat.Fstypename))
    for _,c:=range stat.Fstypename{
        if c==0{break}
        name=append(name,byte(c))
    }
    if string(name)!="nullfs" && string(name)!="tmpfs"{
        return fmt.Errorf("C1 RAM: mount is %q, not host tmpfs/nullfs",string(name))
    }
    // FreeBSD sys/mount.h MNT_RDONLY is 0x00000001. Go's syscall package
    // exposes Statfs_t.Flags but not the corresponding MNT_RDONLY constant.
    const freeBSDMntReadOnly uint64 = 0x00000001
    readonly:=stat.Flags&freeBSDMntReadOnly!=0
    if reader&&!readonly{
        return errors.New("C1 RAM: fi-sor shared mount MUST be read-only")
    }
    if !reader&&readonly{
        return errors.New("C1 RAM: fi-ingest shared mount MUST be writable")
    }
    // The host remains responsible for proving nullfs's actual backing
    // mount is tmpfs (and for jail mount/group admission).
    return nil
}
