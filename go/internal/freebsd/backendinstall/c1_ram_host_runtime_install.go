// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Host startup ordering for C1 volatile tmpfs. The fstab host mount is
// noauto; an explicitly enabled host rc service mounts it AFTER FILESYSTEMS
// and BEFORE jail so no jail nullfs ever sees an unmounted ZFS directory.
// Installation is OFF by default and never starts a mount or jail.
package backendinstall

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

const c1RAMHostServiceName="fi_c1_ram"
const c1RAMHostServiceConfig="# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1\n"+
    "# FI-ROLE: c1-ram-host-runtime-config\n"+
    "# DEVELOPMENT ONLY. Start ONLY after host fstab and jail-mount acceptance.\n"+
    "fi_c1_ram_enable=\"NO\"\n"

// A host rc script is critical to prevent a boot-time race between tmpfs
// creation and the two jail fstab nullfs mounts. The service NEVER unmounts
// the source while the two jails might be using it.
func renderC1RAMHostRC(uid,gid uint64)string{
    return fmt.Sprintf(`#!/bin/sh
# FI-MANAGED: ironsignal-fi-freebsd-runtime-v1
# FI-ROLE: c1-ram-host-rc-service
#
# PROVIDE: fi_c1_ram
# REQUIRE: FILESYSTEMS
# BEFORE: jail
# KEYWORD: shutdown
. /etc/rc.subr
name="fi_c1_ram"
rcvar="fi_c1_ram_enable"
load_rc_config "$name"
: ${fi_c1_ram_enable:="NO"}
start_cmd="fi_c1_ram_start"
stop_cmd="fi_c1_ram_stop"
fi_c1_ram_start()
{
    root="/var/run/fi-c1-handoff"
    # The mountpoint directory may be volatile at host startup.
    [ ! -L "$root" ] || { echo "C1 RAM: mountpoint symlink" >&2; return 1; }
    /usr/bin/install -d -o %d -g %d -m 0770 "$root" || return 1
    # Never cover another filesystem or an already active mount. Read-only
    # preflight after the two jails start proves the final tmpfs/nullfs roles.
    if /sbin/mount -p | /usr/bin/awk -v dir="$root" '$2==dir {found=1} END{exit !found}'; then
        echo "C1 RAM: mountpoint already has a filesystem; refusing remount" >&2
        return 1
    fi
    /sbin/mount "$root" || return 1
    if ! /sbin/mount -p | /usr/bin/awk -v dir="$root" '$2==dir && $3=="tmpfs" {found=1} END{exit !found}'; then
        echo "C1 RAM: host mount is not tmpfs; blocking jail activation" >&2
        return 1
    fi
}
fi_c1_ram_stop()
{
    # Refuse implicit unmount: late SQL replay and RO custody mounts must
    # stop with their own jail lifecycle. RAM disappears on host power loss.
    :
}
run_rc_command "$1"
`,uid,gid)
}
func buildC1RAMHostRuntimePlan(config Config)(runtimePlan,error){
    p,err:=RenderC1RAMMountPlan(config)
    if err!=nil{return runtimePlan{},err}
    if p.HostRoot!=c1RAMHostDirectory{
        return runtimePlan{},errors.New("FI C1 RAM host: unexpected volatile root")
    }
    uid,err:=parsePositiveDecimal("FI_RUNTIME_UID",config.Value("FI_RUNTIME_UID"))
    if err!=nil{return runtimePlan{},err}
    gid,err:=parsePositiveDecimal("FI_RUNTIME_GID",config.Value("FI_RUNTIME_GID"))
    if err!=nil{return runtimePlan{},err}
    script:=renderC1RAMHostRC(uid,gid)
    if !strings.Contains(script,"# BEFORE: jail")||
        !strings.Contains(script,"# REQUIRE: FILESYSTEMS")||
        !strings.Contains(script,"fi_c1_ram_enable")||
        !strings.Contains(script,"/sbin/mount \"$root\"")||
        strings.Contains(script,"umount"){
        return runtimePlan{},errors.New("FI C1 RAM host: unsafe startup ordering or unmount")
    }
    return runtimePlan{
        Parents:[]lifecycleParentSpec{
            {Path:"/usr/local/etc/rc.d",Role:"c1-ram-host-rc-directory",UID:0,GID:0,Mode:0755},
            {Path:"/etc/rc.conf.d",Role:"c1-ram-host-rc-config-directory",UID:0,GID:0,Mode:0755},
        },
        Files:[]runtimeFileSpec{
            {Target:filepath.Join("/usr/local/etc/rc.d",c1RAMHostServiceName),
                Role:"c1-ram-host-rc-service",Content:[]byte(script),Mode:0555,UID:0,GID:0},
            {Target:filepath.Join("/etc/rc.conf.d",c1RAMHostServiceName),
                Role:"c1-ram-host-runtime-config",Content:[]byte(c1RAMHostServiceConfig),
                Mode:0644,UID:0,GID:0},
        },
    },nil
}
func ApplyC1RAMHostRuntime(config Config)error{
    if err:=requireHostFileHost(config,systemHostProbe{});err!=nil{return err}
    plan,err:=buildC1RAMHostRuntimePlan(config)
    if err!=nil{return err}
    if err=preclassifyRuntimePlan(plan);err!=nil{return err}
    for _,p:=range plan.Parents{
        switch state:=classifyLifecycleParent(p);state{
        case lifecycleParentDirectoryMatch:
        case lifecycleParentAbsent:
            if err=createLifecycleParent(p);err!=nil{return err}
        default:return fmt.Errorf("FI C1 RAM host: unsafe directory %s (%s)",p.Role,state)
        }
    }
    for _,f:=range plan.Files{
        switch state:=classifyRuntimeFile(f);state{
        case runtimeFileOwnedMatch:
        case runtimeFileAbsent:
            if err=publishAbsentRuntimeFile(f);err!=nil{return err}
        default:return fmt.Errorf("FI C1 RAM host: unmanaged runtime %s (%s)",f.Role,state)
        }
    }
    return verifyRuntimePlan(plan)
}
func VerifyC1RAMHostRuntime(config Config)error{
    if err:=requireHostFileHost(config,systemHostProbe{});err!=nil{return err}
    plan,err:=buildC1RAMHostRuntimePlan(config)
    if err!=nil{return err}
    return verifyRuntimePlan(plan)
}
// Ensure the test demonstrates this installer does not mount, change
// PostgreSQL, or enable any service. Actual host runtime is FreeBSD only.
var _ = os.ErrNotExist
