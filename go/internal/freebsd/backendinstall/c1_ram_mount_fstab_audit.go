// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Read-only FreeBSD C1 RAM mount fstab collision audit. Never modifies the
// original host/jail fstab and NEVER mounts or starts a service.
package backendinstall

import (
    "errors"
    "fmt"
    "os"
    "strings"
)
type C1FSTABEntryState string
const (
    C1FSTABAbsent C1FSTABEntryState="ABSENT"
    C1FSTABExact C1FSTABEntryState="EXACT"
)
type C1RAMFSTABInspection struct{
    Host C1FSTABEntryState
    Ingest C1FSTABEntryState
    SoR C1FSTABEntryState
}
func inspectC1RAMFSTAB(path,target,expected string)(C1FSTABEntryState,error){
    if path==""||target==""||expected==""{
        return "",errors.New("FI C1 RAM fstab: exact source/target/entry required")
    }
    st,err:=os.Lstat(path)
    if errors.Is(err,os.ErrNotExist){return C1FSTABAbsent,nil}
    if err!=nil{return "",err}
    if !st.Mode().IsRegular()||st.Mode()&os.ModeSymlink!=0||
        st.Size()>1024*1024{
        return "",fmt.Errorf("FI C1 RAM fstab: unsafe existing file %s",path)
    }
    raw,err:=os.ReadFile(path)
    if err!=nil{return "",err}
    want:=strings.Fields(expected)
    if len(want)!=6||want[1]!=target{
        return "",errors.New("FI C1 RAM fstab: invalid expected mount")
    }
    found:=0
    for _,line:=range strings.Split(string(raw),"\n"){
        clean:=strings.TrimSpace(line)
        if clean==""||strings.HasPrefix(clean,"#"){continue}
        fields:=strings.Fields(clean)
        if len(fields)<2{
            return "",fmt.Errorf("FI C1 RAM fstab: malformed entry in %s",path)
        }
        // Any mount to our target, or any reuse of the selected source
        // with inconsistent options, must be examined by an operator.
        if fields[1]!=target{continue}
        if len(fields)!=6||strings.Join(fields," ")!=strings.Join(want," "){
            return "",fmt.Errorf("FI C1 RAM fstab: conflicting or foreign mount for %s in %s",target,path)
        }
        found++
        if found>1{
            return "",fmt.Errorf("FI C1 RAM fstab: duplicate exact mount for %s",target)
        }
    }
    if found==0{return C1FSTABAbsent,nil}
    return C1FSTABExact,nil
}
// InspectC1RAMFSTABPlan is observational only. Host tmpfs uses /etc/fstab;
// the two original configured jail fstab files remain otherwise untouched.
func InspectC1RAMFSTABPlan(plan C1RAMMountPlan)(C1RAMFSTABInspection,error){
    var result C1RAMFSTABInspection
    if plan.HostRoot!=c1RAMHostDirectory||
        plan.IngestFSTAB==""||plan.SoRFSTAB==""||
        plan.IngestFSTAB==plan.SoRFSTAB||
        plan.IngestMount==""||plan.SoRMount==""{
        return result,errors.New("FI C1 RAM fstab: incomplete validated mount plan")
    }
    var err error
    result.Host,err=inspectC1RAMFSTAB("/etc/fstab",plan.HostRoot,plan.HostFSTABEntry)
    if err!=nil{return C1RAMFSTABInspection{},err}
    result.Ingest,err=inspectC1RAMFSTAB(plan.IngestFSTAB,plan.IngestMount,plan.IngestEntry)
    if err!=nil{return C1RAMFSTABInspection{},err}
    result.SoR,err=inspectC1RAMFSTAB(plan.SoRFSTAB,plan.SoRMount,plan.SoREntry)
    if err!=nil{return C1RAMFSTABInspection{},err}
    return result,nil
}
