// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Explicit, OFFLINE FreeBSD C1 host and two-jail fstab entry installation.
// All three files are preflighted before the first rename; each replacement
// is atomically published and fsynced on the *control* filesystem. No RAM
// data is durable, no mount is started, no jail or rc service is enabled,
// and no original receiver custody or SQL connection is opened.
package backendinstall

import (
    "bytes"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "syscall"
)

type c1StagedFSTAB struct {
    target string
    temporary string
    original []byte
    existed bool
}
func c1PlanStagedFSTAB(path,target,entry string)(c1StagedFSTAB,error){
    var staged c1StagedFSTAB
    if !filepath.IsAbs(path)||filepath.Clean(path)=="/"||
        !filepath.IsAbs(target)||target=="/"{
        return staged,errors.New("C1 fstab install: exact absolute file and mountpoint required")
    }
    state,err:=inspectC1RAMFSTAB(path,target,entry)
    if err!=nil{return staged,err}
    if state==C1FSTABExact {
        return c1StagedFSTAB{target:path},nil
    }
    var previous []byte
    fileMode:=os.FileMode(0644)
    var uid,gid int
    info,err:=os.Lstat(path)
    switch{
    case errors.Is(err,os.ErrNotExist):
        // Empty, owner-created jail-specific fstab is allowed. Host
        // /etc/fstab must already exist before C1 may modify it.
        if path=="/etc/fstab" {
            return staged,errors.New("C1 fstab install: system /etc/fstab is missing")
        }
    case err!=nil:
        return staged,err
    default:
        if !info.Mode().IsRegular()||info.Mode()&os.ModeSymlink!=0||
            info.Size()>1024*1024{
            return staged,errors.New("C1 fstab install: existing host/jail fstab is unsafe")
        }
        previous,err=os.ReadFile(path)
        if err!=nil{return staged,err}
        if int64(len(previous))!=info.Size(){
            return staged,errors.New("C1 fstab install: fstab changed during preflight")
        }
        stat,ok:=info.Sys().(*syscall.Stat_t)
        if !ok{return staged,errors.New("C1 fstab install: native file owner unavailable")}
        uid,gid=int(stat.Uid),int(stat.Gid)
        fileMode=info.Mode().Perm()
    }
    // Never parse/normalize/reorder existing unrelated host or jail mounts.
    // The exact C1 entry is appended after an existing newline if needed.
    appended:=make([]byte,0,len(previous)+len(entry)+2)
    appended=append(appended,previous...)
    if len(previous)>0&&previous[len(previous)-1]!='\n' {
        appended=append(appended,'\n')
    }
    appended=append(appended,entry...)
    appended=append(appended,'\n')
    directory:=filepath.Dir(path)
    st,err:=os.Lstat(directory)
    if err!=nil||!st.IsDir()||st.Mode()&os.ModeSymlink!=0{
        return staged,errors.New("C1 fstab install: unsafe destination directory")
    }
    temp,err:=os.CreateTemp(directory,".fi-c1-ram-fstab-")
    if err!=nil{return staged,err}
    success:=false
    defer func(){if !success{_ =os.Remove(temp.Name())}}()
    if _,err=temp.Write(appended);err!=nil{
        temp.Close();return staged,err
    }
    if err=temp.Chmod(fileMode);err!=nil{
        temp.Close();return staged,err
    }
    if info!=nil && os.Geteuid()==0 {
        if err=temp.Chown(uid,gid);err!=nil{
            temp.Close();return staged,err
        }
    }
    if err=temp.Sync();err!=nil{
        temp.Close();return staged,err
    }
    if err=temp.Close();err!=nil{return staged,err}
    success=true
    return c1StagedFSTAB{
        target:path,temporary:temp.Name(),original:previous,existed:info!=nil,
    },nil
}
func c1ApplyStagedFSTAB(stage c1StagedFSTAB)error{
    if stage.target==""{return errors.New("C1 fstab install: missing target")}
    if stage.temporary==""{return nil}
    // Re-read the original bytes just before replacement. No changed,
    // symlinked or newly created fstab may silently be overwritten.
    data,err:=os.ReadFile(stage.target)
    if stage.existed{
        if err!=nil||!bytes.Equal(data,stage.original){
            return errors.New("C1 fstab install: destination was changed after staged preflight")
        }
        st,e:=os.Lstat(stage.target)
        if e!=nil||!st.Mode().IsRegular()||st.Mode()&os.ModeSymlink!=0{
            return errors.New("C1 fstab install: destination substituted after preflight")
        }
    }else if !errors.Is(err,os.ErrNotExist){
        return errors.New("C1 fstab install: destination unexpectedly exists")
    }
    if err=os.Rename(stage.temporary,stage.target);err!=nil{return err}
    // Atomic rename needs a durable directory entry; this fsync is for
    // host *configuration*, NEVER for volatile C1 RAM object storage.
    parent,err:=os.Open(filepath.Dir(stage.target))
    if err!=nil{return err}
    syncErr:=parent.Sync()
    closeErr:=parent.Close()
    if syncErr!=nil{return syncErr}
    return closeErr
}

// ApplyC1RAMFSTABPlan is OFFLINE operator-initiated only. If the third
// rename fails after one earlier successful rename, C1 remains disabled
// and the operator may re-run idempotently after inspecting the resulting
// exact entries. No attempt is made to undo unrelated existing fstab lines.
func ApplyC1RAMFSTABPlan(config Config)error{
    if err:=requireHostFileHost(config,systemHostProbe{});err!=nil{return err}
    if os.Getenv("FI_C1_RAM_FSTAB_APPROVED")!="EXACT_C1_MOUNT_PLAN_REVIEWED"{
        return errors.New("C1 fstab install: explicit exact plan approval required")
    }
    plan,err:=RenderC1RAMMountPlan(config)
    if err!=nil{return err}
    if _,err=InspectC1RAMFSTABPlan(plan);err!=nil{return err}
    changes:=[]struct{path,target,entry string}{
        {"/etc/fstab",plan.HostRoot,plan.HostFSTABEntry},
        {plan.IngestFSTAB,plan.IngestMount,plan.IngestEntry},
        {plan.SoRFSTAB,plan.SoRMount,plan.SoREntry},
    }
    staged:=make([]c1StagedFSTAB,0,len(changes))
    defer func(){
        for _,item:=range staged{
            if item.temporary!=""{_ =os.Remove(item.temporary)}
        }
    }()
    // All three must be safe and fully staged before ANY fstab mutation.
    for _,item:=range changes{
        next,e:=c1PlanStagedFSTAB(item.path,item.target,item.entry)
        if e!=nil{return fmt.Errorf("C1 fstab install: staged preflight %s: %w",item.path,e)}
        staged=append(staged,next)
    }
    for _,item:=range staged{
        if err=c1ApplyStagedFSTAB(item);err!=nil{
            return fmt.Errorf("C1 fstab install: stop after partial atomic fstab apply at %s (C1 remains OFF; inspect and re-run): %w",
                item.target,err)
        }
    }
    final,err:=InspectC1RAMFSTABPlan(plan)
    if err!=nil{return err}
    if final.Host!=C1FSTABExact||final.Ingest!=C1FSTABExact||
        final.SoR!=C1FSTABExact{
        return errors.New("C1 fstab install: exact post-apply entries not verified")
    }
    return nil
}
