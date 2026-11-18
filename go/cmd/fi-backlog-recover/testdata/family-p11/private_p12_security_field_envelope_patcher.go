// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// EXACT-anchor disposable C220 clone field-COPY envelope experiment.
// This executable NEVER edits the historical seed, repository checkout,
// production SoR or any installed service. It is built only for fi-dev.
package main

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

func main() {
    if len(os.Args)!=2 { fail(errors.New("FI P12: expected disposable optimized-source root")) }
    root:=filepath.Clean(os.Args[1])
    if !filepath.IsAbs(root) ||
        !strings.HasPrefix(root,"/home/jwood/fi-window-bench-w512-family-p3-") ||
        !strings.HasSuffix(root,"/optimized-source") ||
        strings.Contains(root,"..") {
        fail(errors.New("FI P12: refusing non-disposable optimized source root"))
    }
    path:=filepath.Join(root,"go/internal/recordingest/security_field_profile_dual.go")
    stat,err:=os.Lstat(path)
    if err!=nil||!stat.Mode().IsRegular(){fail(fmt.Errorf("FI P12: missing regular original field profile: %v",err))}
    bytes,err:=os.ReadFile(path)
    if err!=nil{fail(err)}
    text:=string(bytes)
    changes:=[]struct{old,new string}{
        {
            "if securityBulkLimitsFromContext(ctx).Name == \"P3\" {\n\t\treturn 32768\n\t}",
            "if securityBulkLimitsFromContext(ctx).Name == \"P3\" {\n\t\tif privateP12SecurityFieldEnvelopeSelected(ctx) {return 65536}\n\t\treturn 32768\n\t}",
        },
        {
            "if securityBulkLimitsFromContext(ctx).Name == \"P3\" {\n\t\treturn 8 << 20\n\t}",
            "if securityBulkLimitsFromContext(ctx).Name == \"P3\" {\n\t\tif privateP12SecurityFieldEnvelopeSelected(ctx) {return 16 << 20}\n\t\treturn 8 << 20\n\t}",
        },
    }
    for _,ch:=range changes {
        if strings.Count(text,ch.old)!=1{
            fail(fmt.Errorf("FI P12: exact original P3 field budget anchor missing; no edits performed"))
        }
        text=strings.Replace(text,ch.old,ch.new,1)
    }
    temp:=path+".p12-field.tmp"
    if _,err:=os.Lstat(temp);!errors.Is(err,os.ErrNotExist){
        fail(errors.New("FI P12: refuse temporary file collision"))
    }
    if err:=os.WriteFile(temp,[]byte(text),stat.Mode().Perm());err!=nil{fail(err)}
    if err:=os.Rename(temp,path);err!=nil{_ =os.Remove(temp);fail(err)}
    fmt.Println("FI P12 PRIVATE FIELD ENVELOPE PATCH PASS original_P3_rows=32768 original_P3_bytes=8388608 P12_rows=65536 P12_bytes=16777216 source_clone_only=true")
}
func fail(err error){fmt.Fprintln(os.Stderr,err);os.Exit(1)}
