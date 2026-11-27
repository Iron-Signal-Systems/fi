// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Pure C1 FreeBSD tmpfs/nullfs MOUNT PLAN; no syscalls and no host mutation.
// The host mounts tmpfs BEFORE starting jails; FreeBSD jail.fstab owns each
// nullfs view. No user, jail or worker gains allow.mount privileges.
// The plan never installs, launches or edits the original signed custody.
package backendinstall

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

const c1RAMHostDirectory="/var/run/fi-c1-handoff"
const c1RAMJailDirectory="/var/run/fi-c1-handoff"
const c1RAMMountSizeGiB=4

type C1RAMMountPlan struct {
    HostRoot string
    IngestMount string
    SoRMount string
    IngestFSTAB string
    SoRFSTAB string
    HostFSTABEntry string
    IngestEntry string
    SoREntry string
    BytesCeiling uint64
}

// RenderC1RAMMountPlan is read-only and uses the FI installer's exact jail
// roots and numeric runtime identities, not hardcoded C220 jail paths.
// The 4 GiB filesystem cap exceeds the independent 2 GiB completed-buffer
// credit cap, leaving headroom for partially written RAM objects.
func RenderC1RAMMountPlan(cfg Config)(C1RAMMountPlan,error){
    var p C1RAMMountPlan
    uid,err:=parsePositiveDecimal("FI_RUNTIME_UID",cfg.Value("FI_RUNTIME_UID"))
    if err!=nil{return p,err}
    gid,err:=parsePositiveDecimal("FI_RUNTIME_GID",cfg.Value("FI_RUNTIME_GID"))
    if err!=nil{return p,err}
    if uid<1000||uid>32000||gid<1000||gid>32000{
        return p,errors.New("FI C1 RAM mount: runtime identity outside jail policy")
    }
    ingest:=cfg.Value("FI_INGEST_ROOT")
    sor:=cfg.Value("FI_SOR_DB_ROOT")
    if !filepath.IsAbs(ingest)||!filepath.IsAbs(sor)||
        filepath.Clean(ingest)=="/"||filepath.Clean(sor)=="/"||
        filepath.Clean(ingest)==filepath.Clean(sor)||
        strings.ContainsAny(ingest," \t\n")||strings.ContainsAny(sor," \t\n"){
        return p,errors.New("FI C1 RAM mount: distinct safe absolute jail roots required")
    }
    // Jail root ownership is independently checked by the host installer;
    // the pure planner additionally prohibits symlink substitution.
    for _,root:=range []string{ingest,sor}{
        st,e:=os.Lstat(root)
        if e!=nil{return p,fmt.Errorf("FI C1 RAM mount: jail root missing: %w",e)}
        if !st.IsDir()||st.Mode()&os.ModeSymlink!=0{
            return p,errors.New("FI C1 RAM mount: unsafe jail root")
        }
    }
    ingestFSTAB,sorFSTAB:=cfg.Value("FI_INGEST_FSTAB"),cfg.Value("FI_SOR_DB_FSTAB")
    if !filepath.IsAbs(ingestFSTAB)||!filepath.IsAbs(sorFSTAB)||
        ingestFSTAB==sorFSTAB||
        strings.ContainsAny(ingestFSTAB," \t\n")||
        strings.ContainsAny(sorFSTAB," \t\n"){
        return p,errors.New("FI C1 RAM mount: separate host jail fstab files required")
    }
    p.HostRoot=c1RAMHostDirectory
    p.IngestMount=filepath.Join(ingest,"var/run/fi-c1-handoff")
    p.SoRMount=filepath.Join(sor,"var/run/fi-c1-handoff")
    p.IngestFSTAB=filepath.Clean(ingestFSTAB)
    p.SoRFSTAB=filepath.Clean(sorFSTAB)
    p.BytesCeiling=c1RAMMountSizeGiB<<30
    // Host fstab is noauto. The service-activation procedure explicitly
    // mounts and checks tmpfs BEFORE enabling either jail nullfs fstab.
    p.HostFSTABEntry=fmt.Sprintf(
        "tmpfs %s tmpfs rw,noauto,nosuid,noexec,size=%dg,uid=%d,gid=%d,mode=0770 0 0",
        p.HostRoot,c1RAMMountSizeGiB,uid,gid)
    p.IngestEntry=fmt.Sprintf("%s %s nullfs rw 0 0",p.HostRoot,p.IngestMount)
    p.SoREntry=fmt.Sprintf("%s %s nullfs ro 0 0",p.HostRoot,p.SoRMount)
    if p.IngestMount==p.SoRMount||p.IngestMount==p.HostRoot||
        p.SoRMount==p.HostRoot{
        return C1RAMMountPlan{},errors.New("FI C1 RAM mount: overlapping source/destination")
    }
    return p,nil
}
