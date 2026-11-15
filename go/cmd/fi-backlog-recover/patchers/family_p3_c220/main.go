// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Exact-anchor disposable W512 family-P3 overlay. NEVER edit an installed FI tree.
package main

import (
  "errors"
  "fmt"
  "os"
  "path/filepath"
  "strings"
)

func main() {
  // "audit" performs the same ordered, in-memory exact-anchor checks
  // against the ORIGINAL read-only seed. It never writes even a temp file.
  audit:=len(os.Args)==3 && os.Args[1]=="audit"
  if len(os.Args)!=2 && !audit {
    fmt.Fprintln(os.Stderr,"FI FAMILY P3 PATCH STOP: expected disposable root or audit original seed root")
    os.Exit(2)
  }
  arg:=os.Args[1]
  if audit {arg=os.Args[2]}
  root:=filepath.Clean(arg)
  disposable:=filepath.IsAbs(root) && strings.HasPrefix(root,"/home/jwood/fi-window-bench-w512-family-p3-") &&
    strings.HasSuffix(root,"/optimized-source") && !strings.Contains(root,"..")
  original:=root=="/home/jwood/fi-window-bench-w512-20261115T153532Z/optimized-source"
  if (audit && !original) || (!audit && !disposable) {
    fmt.Fprintln(os.Stderr,"FI FAMILY P3 PATCH STOP: root is not an allowed isolated source")
    os.Exit(1)
  }
  // Match the unique struct declaration, independent of gofmt indentation.
  edits:=[]struct{path,old,new string}{
    {
      "go/internal/recordingest/private_parallel_preparation.go",
      "type privateParallelLine struct {",
      "type privateParallelLine struct {\n    headerKind string\n    headerFamily spoolDispatchFamily",
    },
    {
      "go/internal/recordingest/postgres_ingest.go",
      "parallelPrep, err = newPrivateParallelPreparedStream(ctx, reader, privateParallelAPrepare)",
      "parallelPrep, err = newPrivateFamilyP3PreparedStream(ctx, reader, privateFamilyP3Prepare)",
    },
    {
      "go/internal/recordingest/postgres_ingest.go",
      "if parallelPrep.rows != ordinal {",
      "profile.Read += parallelPrep.readerTime\n\t\tif parallelPrep.rows != ordinal {",
    },
    {
      "go/internal/recordingest/private_parallel_preparation.go",
      "type privateParallelPreparedStream struct {",
      "type privateParallelPreparedStream struct {\n    privateFamilyBudget *privateFamilyP3Budget",
    },
    {
      "go/internal/recordingest/private_parallel_preparation.go",
      "line.ordinal > s.nextOrdinal+privateParallelAMaxInFlight-1",
      "line.ordinal > s.nextOrdinal+int64(cap(s.credits))-1",
    },
    {
      "go/internal/recordingest/private_parallel_preparation.go",
      "func (s *privateParallelPreparedStream) record(line privateParallelLine) {",
      "func (s *privateParallelPreparedStream) record(line privateParallelLine) {\n    if s.privateFamilyBudget != nil {s.privateFamilyBudget.release(int64(len(line.raw)))}",
    },
    {
      "go/internal/recordingest/record.go",
      "type SourceRecord struct {",
      "type SourceRecord struct {\n    PrivateFamilyP3File *fileObservationPayload\n    PrivateFamilyP3Coverage *privateFamilyP3CoverageValue",
    },
    {
      "go/internal/recordingest/postgres_ingest.go",
      "if err := decodeStrictPayload(item.prepared.Record.Payload, &value); err != nil {",
      "if item.prepared.PrivateFamilyP3File != nil {\n                value = *item.prepared.PrivateFamilyP3File\n            } else if err := decodeStrictPayload(item.prepared.Record.Payload, &value); err != nil {",
    },
    {
      "go/internal/recordingest/security_coverage_bulk.go",
      "if err := decodeStrictPayload(prepared.Record.Payload, &value); err != nil {",
      "if prepared.PrivateFamilyP3Coverage != nil {\n        value = prepared.PrivateFamilyP3Coverage.value\n    } else if err := decodeStrictPayload(prepared.Record.Payload, &value); err != nil {",
    },
    {
      "go/internal/recordingest/private_parallel_preparation.go",
      "func (s *privateParallelPreparedStream) Close() {",
      "func (s *privateParallelPreparedStream) Close() {\n    if s != nil && s.privateFamilyBudget != nil {\n        defer func(){ used,peak:=s.privateFamilyBudget.stats(); fmt.Printf(\"FI FAMILY P3 BUDGET peak_pending_bytes=%d remaining_bytes=%d\\n\",peak,used) }()\n    }",
    },
    {
      "go/internal/recordingest/postgres_ingest.go",
      "if err := ntfs.ValidateObservation(value.NTFS); err != nil {",
      "if item.prepared.PrivateFamilyP3File == nil {\n                if err := ntfs.ValidateObservation(value.NTFS); err != nil {",
    },
    {
      "go/internal/recordingest/postgres_ingest.go",
      "if value.NTFS.GovernedRoot.ScopeID != item.prepared.Record.ScopeID {",
      "}\n            if value.NTFS.GovernedRoot.ScopeID != item.prepared.Record.ScopeID {",
    },
    {
      "go/internal/recordingest/private_parallel_preparation.go",
      "s.readerTime += line.readTime",
      "if s.privateFamilyBudget == nil {s.readerTime += line.readTime}",
    },
  }
  files:=map[string]string{}
  perms:=map[string]os.FileMode{}
  mismatches:=0
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
    if n:=strings.Count(files[path],e.old);n!=1 {
      // Include the unique expected source fragment in error output. Merely
      // reporting the file path concealed which of several edits failed.
      fmt.Fprintf(os.Stderr,"FI FAMILY P3 ANCHOR MISMATCH path=%s expected=%q count=%d audit=%t\n",e.path,e.old,n,audit)
      if n==0 {
        for _,line:=range strings.Split(files[path],"\n") {
          if strings.Contains(line,"parallelPrep") ||
             strings.Contains(line,"ntfs.ValidateObservation") ||
             strings.Contains(line,"decodeStrictPayload") ||
             strings.Contains(line,"GovernedRoot.ScopeID") ||
             strings.Contains(line,"readerTime") {
            fmt.Fprintf(os.Stderr,"FI FAMILY P3 ANCHOR NEARBY %s: %s\n",e.path,strings.TrimSpace(line))
          }
        }
      }
      if !audit { fail(fmt.Errorf("anchor %s count=%d wanted=1; original signed seed unchanged",e.path,n)) }
      mismatches++
      continue
    }
    files[path]=strings.Replace(files[path],e.old,e.new,1)
  }
  if mismatches != 0 { fail(fmt.Errorf("read-only seed anchor audit found %d incompatible edits; no source changed",mismatches)) }
  if audit {
    fmt.Printf("FI FAMILY P3 ORIGINAL SEED ANCHOR AUDIT PASS edits=%d files=%d unchanged=true\n",len(edits),len(files))
    return
  }
  // Require both classifier implementation and its fixture-bearing test.
  // Missing tests are failures, never grounds to weaken the Go test gate.
  for _,n:=range []string{"private_canonical_spool_dispatch.go","private_canonical_spool_dispatch_test.go","private_header_first_p2.go","private_header_first_p2_test.go","private_family_preparation_p3.go","private_family_preparation_p3_test.go"} {
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
  fmt.Printf("FI FAMILY P3 W512 PRIVATE PATCH PASS source_files=%d modifications=%d readonly_spool=true family_lanes=5 security_workers=2 credits=32 writer=original_H16 atomic=true\n",len(files),len(edits))
}
func fail(err error){ fmt.Fprintln(os.Stderr,"FI FAMILY P3 PATCH STOP:",err);os.Exit(1) }
