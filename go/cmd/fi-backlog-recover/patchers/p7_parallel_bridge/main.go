// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Exact-anchor, private-clone-only bridge for P7's independent five-SQL
// writer signed reader. The established Candidate A profile remains strict.
package main

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

func main() {
    if len(os.Args)!=2 {stop(errors.New("expected one disposable source root"))}
    root:=filepath.Clean(os.Args[1])
    if !filepath.IsAbs(root) ||
        !(strings.HasPrefix(root,"/home/jwood/fi-window-bench-w512-family-p3-") ||
          strings.HasPrefix(root,"/home/jwood/fi-p7-five-writer-go-tests-")) {
        stop(errors.New("outside the P7 disposable source namespaces"))
    }
    path:=filepath.Join(root,"go/internal/recordingest/private_parallel_preparation.go")
    p7:=filepath.Join(root,"go/internal/recordingest/private_p7_typed_window.go")
    st,err:=os.Lstat(path)
    if err!=nil || !st.Mode().IsRegular() {stop(fmt.Errorf("expected regular private preparer: %v",err))}
    p7st,err:=os.Lstat(p7)
    if err!=nil || !p7st.Mode().IsRegular() {stop(errors.New("P7 source overlay missing"))}
    p7bytes,err:=os.ReadFile(p7)
    if err!=nil || !strings.Contains(string(p7bytes),"func privateP7ParallelPreparationReader(") {
        stop(errors.New("P7 reader ownership gate unavailable"))
    }
    original,err:=os.ReadFile(path)
    if err!=nil {stop(err)}
    const anchor="return privateParallelARequested(ctx) &&\n        privateDependencyBuffersEnabled(ctx) &&"
    const bridge="return privateParallelARequested(ctx) &&\n        (privateDependencyBuffersEnabled(ctx) || privateP7ParallelPreparationReader(ctx)) &&"
    if strings.Count(string(original),anchor)!=1 ||
        strings.Contains(string(original),bridge) {
        stop(errors.New("Candidate A exact activation anchor changed or already patched"))
    }
    next:=strings.Replace(string(original),anchor,bridge,1)
    tmp:=path+".p7-bridge-tmp"
    if _,err:=os.Lstat(tmp);!errors.Is(err,os.ErrNotExist){
        stop(errors.New("P7 patch destination already exists"))
    }
    if err:=os.WriteFile(tmp,[]byte(next),st.Mode().Perm());err!=nil {stop(err)}
    if err:=os.Rename(tmp,path);err!=nil {os.Remove(tmp);stop(err)}
    fmt.Println("FI P7 PREPARER BRIDGE PATCH PASS legacy_k32_unchanged=true private_p7_guard=required original_h16_profile=required")
}

func stop(err error){
    fmt.Fprintln(os.Stderr,"FI P7 PREPARER BRIDGE STOP:",err)
    os.Exit(1)
}
