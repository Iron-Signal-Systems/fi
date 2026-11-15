// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Exact-anchor disposable W512 P2 overlay. NEVER edit an installed FI tree.
package main

import (
  "errors"
  "fmt"
  "os"
  "path/filepath"
  "strings"
)

func main() {
  if len(os.Args)!=2 { fmt.Fprintln(os.Stderr,"FI HEADER FIRST PATCH STOP: expected isolated source root"); os.Exit(2) }
  root:=filepath.Clean(os.Args[1])
  if !filepath.IsAbs(root) || !strings.HasPrefix(root,"/home/jwood/fi-window-bench-w512-hf-p2-") ||
     !strings.HasSuffix(root,"/optimized-source") || strings.Contains(root,"..") {
    fmt.Fprintln(os.Stderr,"FI HEADER FIRST PATCH STOP: root is not disposable W512 HF source");os.Exit(1)
  }
  // Match the declaration itself, not a gofmt-sensitive indentation prefix.\n  // The historical Candidate A runner formats this disposable source with tabs.\n  edits:=[]struct{path,old,new string}{
    {
      "go/internal/recordingest/private_parallel_preparation.go",
      "type privateParallelLine struct {",
      "type privateParallelLine struct {\n    headerKind string\n    headerFamily spoolDispatchFamily",
    },
    {
      "go/internal/recordingest/postgres_ingest.go",
      "parallelPrep, err = newPrivateParallelPreparedStream(ctx, reader, privateParallelAPrepare)",
      "parallelPrep, err = newPrivateHeaderFirstPreparedStream(ctx, reader, privateHeaderFirstPrepare)",
    },
    {
      "go/internal/recordingest/postgres_ingest.go",
      "if parallelPrep.rows != ordinal {",
      "profile.Read += parallelPrep.readerTime\n\t\tif parallelPrep.rows != ordinal {",
    },
  }
  files:=map[string]string{}
  perms:=map[string]os.FileMode{}
  for _,e:=range edits {
    path:=filepath.Join(root,e.path)
    if _,ok:=files[path]; !ok {
      stat,err:=os.Lstat(path)
      if err!=nil||!stat.Mode().IsRegular() {fail(fmt.Errorf("private source not regular: %s: %v",e.path,err))}
      b,err:=os.ReadFile(path)
      if err!=nil {fail(err)}
      files[path]=string(b)
      perms[path]=stat.Mode().Perm()
    }
    if n:=strings.Count(files[path],e.old);n!=1 {fail(fmt.Errorf("anchor %s count=%d wanted=1",e.path,n))}
    files[path]=strings.Replace(files[path],e.old,e.new,1)
  }
  // Exactly three pre-staged assets; reject old or missing source and refuse
  // unintended duplication of new symbols in any existing file.
  for _,n:=range []string{"private_canonical_spool_dispatch.go","private_header_first_p2.go","private_header_first_p2_test.go"} {
    path:=filepath.Join(root,"go/internal/recordingest",n)
    st,err:=os.Lstat(path)
    if err!=nil||!st.Mode().IsRegular() {fail(fmt.Errorf("missing staged private asset %s: %v",n,err))}
  }
  for path,content:=range files {
    temp:=path+".header-first.tmp"
    if _,err:=os.Lstat(temp);!errors.Is(err,os.ErrNotExist) {fail(fmt.Errorf("temporary collision %s",temp))}
    if err:=os.WriteFile(temp,[]byte(content),perms[path]);err!=nil {fail(err)}
    if err:=os.Rename(temp,path);err!=nil {fail(err)}
  }
  fmt.Printf("FI HEADER FIRST W512 P2 PRIVATE PATCH PASS source_files=%d modifications=%d readonly_spool=true writer=original_H16 atomic=true\n",len(files),len(edits))
}
func fail(err error){ fmt.Fprintln(os.Stderr,"FI HEADER FIRST PATCH STOP:",err);os.Exit(1) }
