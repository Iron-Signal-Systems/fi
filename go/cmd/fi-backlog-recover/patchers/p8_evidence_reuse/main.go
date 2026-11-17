// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Exact-anchor P8 overlay. Only disposable C220 sources; production never
// builds or invokes this patcher. Historical P7 sources remain unchanged.
package main

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

type edit struct{ path, old, replacement string }

var edits=[]edit{
    {
        "go/internal/recordingest/backlog_verified_cache_recovery.go",
        "if err=StageBacklogSourceAndTypedWindow(ctx,reader,writer,g,limits,window,privateRoot);err!=nil{",
        `stageCtx:=ctx
   // This proof is created ONLY AFTER the already-completed
   // MaterializeBacklogWindow + RecordVerifiedBacklogArtifactWindow.
   // No persisted checkpoint can mint a fresh in-memory proof.
   if privateP7FiveWriterSelected() {
    stageCtx,err=privateP8WithVerifiedOuterArtifact(ctx,privateRoot,d,window)
    if err!=nil{return empty,fmt.Errorf("FI P8: outer verified artifact handoff: %w",err)}
   }
   if err=StageBacklogSourceAndTypedWindow(stageCtx,reader,writer,g,limits,window,privateRoot);err!=nil{`,
    },
    {
        "go/internal/recordingest/backlog_source_window_postgres.go",
        `if err := VerifyMaterializedBacklogWindow(ctx, g, limits, index, privateRoot); err != nil {
        return fmt.Errorf("FI backlog source stage: source copy verification failed: %w", err)
    }`,
        `// StageVerifiedBacklogSourceWindow ALWAYS scans every signed batch,
    // checks its per-batch SHA/count/bytes and hashes all staged SQL rows.
    // Avoid a second full-data preliminary hash only when the SAME
    // operation already finished the exact outer artifact checkpoint.
    if !privateP8OuterEvidenceMatches(ctx,privateRoot,d,index) {
        if err := VerifyMaterializedBacklogWindow(ctx, g, limits, index, privateRoot); err != nil {
            return fmt.Errorf("FI backlog source stage: source copy verification failed: %w", err)
        }
    }`,
    },
}

func main(){
    if len(os.Args)!=3 {fail(errors.New("usage audit|apply /absolute/disposable/optimized-source"))}
    mode,root:=os.Args[1],filepath.Clean(os.Args[2])
    if !filepath.IsAbs(root)||!strings.HasSuffix(root,"/optimized-source"){
        fail(errors.New("source root must be absolute and optimized-source"))
    }
    original:=root=="/home/jwood/fi-window-bench-w512-20261115T153532Z/optimized-source"
    private:=(strings.HasPrefix(root,"/home/jwood/fi-window-bench-w512-family-p3-")||
        strings.HasPrefix(root,"/home/jwood/fi-p7-five-writer-go-tests-")) &&
        !strings.Contains(root,"..")
    if (mode=="audit" && !(private||original)) || (mode=="apply" && !private) {
        fail(errors.New("P8 patching allowed only on verified private disposable roots"))
    }
    if mode=="apply" {
        helper:=filepath.Join(root,"go/internal/recordingest/private_p8_verified_outer.go")
        p7:=filepath.Join(root,"go/internal/recordingest/private_p7_typed_window.go")
        for _,p:=range []string{helper,p7}{
            st,err:=os.Lstat(p)
            if err!=nil||!st.Mode().IsRegular(){fail(fmt.Errorf("missing private P8 source %s: %v",p,err))}
        }
    }
    files:=map[string][]byte{}
    perms:=map[string]os.FileMode{}
    for _,e:=range edits{
        p:=filepath.Join(root,e.path)
        st,err:=os.Lstat(p)
        if err!=nil||!st.Mode().IsRegular() {fail(fmt.Errorf("expected private source %s: %v",e.path,err))}
        old,err:=os.ReadFile(p)
        if err!=nil{fail(err)}
        rewritten,err:=rewrite(old,e)
        if err!=nil{fail(fmt.Errorf("%s: %w",e.path,err))}
        files[p]=rewritten
        perms[p]=st.Mode().Perm()
    }
    if mode=="audit" {
        fmt.Printf("FI P8 EVIDENCE SOURCE AUDIT PASS edits=%d source_unchanged=true\n",len(edits))
        return
    }
    // Every anchor has already passed before the first disposable file edit.
    for _,e:=range edits{
        p:=filepath.Join(root,e.path)
        tmp:=p+".p8-verified.tmp"
        if _,err:=os.Lstat(tmp);!errors.Is(err,os.ErrNotExist) {
            fail(fmt.Errorf("temporary P8 patch collision %s",tmp))
        }
        if err:=os.WriteFile(tmp,files[p],perms[p]);err!=nil{fail(err)}
        if err:=os.Rename(tmp,p);err!=nil {os.Remove(tmp);fail(err)}
    }
    fmt.Println("FI P8 VERIFIED EVIDENCE PATCH PASS outer_checkpoint=reused source_sql_scan=retained typed_canonical_sha=retained clone_only=true")
}

func rewrite(input []byte,e edit)([]byte,error){
    s:=string(input)
    // Seed formatting may be gofmt tabs rather than the short literal
    // captured in the source review. Normalize only the exact initial
    // verification block's whitespace; never relax the function name,
    // digest comparison, or SQL source ledger.
    if strings.Contains(e.path,"backlog_source_window_postgres.go"){
        if strings.Contains(s,"if !privateP8OuterEvidenceMatches(ctx,privateRoot,d,index)") {
            return nil,errors.New("P8 signed-source verification prehash already patched")
        }
        start:=strings.Index(s,"if err := VerifyMaterializedBacklogWindow(ctx, g, limits, index, privateRoot); err != nil {")
        if start<0 || strings.Count(s,"if err := VerifyMaterializedBacklogWindow(ctx, g, limits, index, privateRoot); err != nil {")!=1{
            return nil,errors.New("P8 original full artifact verifier anchor missing")
        }
        end:=strings.Index(s[start:],"}\n")
        if end<0{return nil,errors.New("P8 original verification block incomplete")}
        end+=start+2
        section:=s[start:end]
        if !strings.Contains(section,`return fmt.Errorf("FI backlog source stage: source copy verification failed: %w", err)`) ||
            strings.Count(section,"return fmt.Errorf(")!=1 ||
            strings.Count(section,"}")!=1{
            return nil,errors.New("P8 original artifact verifier unexpectedly changed")
        }
        return []byte(s[:start]+e.replacement+s[end:]),nil
    }
    if strings.Count(s,e.old)!=1 || strings.Contains(s,e.replacement) {
        return nil,errors.New("P8 outer checkpoint handoff anchor changed or already patched")
    }
    return []byte(strings.Replace(s,e.old,e.replacement,1)),nil
}
func fail(err error){fmt.Fprintln(os.Stderr,"FI P8 EVIDENCE PATCH STOP:",err);os.Exit(1)}
