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
  // The C220 seed already has its own optimized File validation pipeline
  // (validated.observation), not the repository's older standalone
  // ntfs.ValidateObservation(value.NTFS) call. Do NOT inject a second
  // validation wrapper or replace scope validation blindly.
  // Instead, reuse worker-decoded value at the exact JSON decode site;
  // leave existing seed validation and relational constraints intact.
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
      "go/internal/recordingest/private_parallel_preparation.go",
      "s.readerTime += line.readTime",
      "if s.privateFamilyBudget == nil {s.readerTime += line.readTime}",
    },
    {
      "go/internal/recordingest/private_parallel_preparation.go",
      "type privateParallelPreparedStream struct {",
      "type privateParallelPreparedStream struct {\n    privateFamilyP3Telemetry *privateFamilyP3Telemetry\n    privateSweepComplete bool",
    },
    {
      "go/internal/recordingest/private_parallel_preparation.go",
      "return privateParallelLine{}, false",
      "s.privateSweepComplete=true\n            return privateParallelLine{}, false",
    },
    {
      "go/internal/recordingest/private_parallel_preparation.go",
      "<-s.done",
      "<-s.done\n    if s.privateFamilyP3Telemetry != nil {s.privateFamilyP3Telemetry.print(s.privateSweepComplete)}",
    },
    {
      "go/internal/recordingest/private_parallel_preparation.go",
      "type privateParallelPreparedStream struct {",
      "type privateParallelPreparedStream struct {\n    privateP5Session *privateP5Session",
    },
    {
      "go/internal/recordingest/private_parallel_preparation.go",
      "if s.privateFamilyP3Telemetry != nil {s.privateFamilyP3Telemetry.print(s.privateSweepComplete)}",
      "if s.privateP5Session != nil {s.privateP5Session.afterClose()}\n    if s.privateFamilyP3Telemetry != nil {s.privateFamilyP3Telemetry.print(s.privateSweepComplete)}",
    },
    {
      "go/internal/recordingest/backlog_typed_window_postgres.go",
      "var chunkSamples []backlogTypedChunkSample",
      "var chunkSamples []backlogTypedChunkSample\n    // P5 is a disposable clone-only option; source chunks keep the same\n    // SQL transaction and signed evidence, while preparation workers now\n    // persist across original signed batch boundaries in this window.\n    if privateP5Enabled() {\n        pool,poolErr:=newPrivateP5Pool(ctx,index)\n        if poolErr!=nil {return poolErr}\n        defer pool.Close()\n        ctx=context.WithValue(ctx,privateP5PoolContextKey{},pool)\n    }",
    },
    // P6 is an isolated extension of P5; the original signed reader,
    // joined-source custody and outer W512 transaction stay intact.
    {
      "go/internal/recordingest/postgres_ingest.go",
      "if profile.coverageBuffer == nil {",
      "if privateP6Selected() && privateP6BuffersFromContext(ctx)==nil {\n        return 0, errors.New(\"FI P6: private W512 buffer context is missing; no fallback to P5 SQL\")\n    }\n    if profile.coverageBuffer == nil {",
    },
    {
      "go/internal/recordingest/postgres_ingest.go",
      "if prepared.Record.RecordKind != \"WindowsSecurityCoverage\" &&",
      "if p6:=privateP6BuffersFromContext(ctx);p6!=nil {\n            joined:=joinedBacklogSourceFromContext(ctx)\n            if joined==nil || joined.batchIndex<0 {\n                return ordinal, errors.New(\"FI P6: signed source batch index unavailable\")\n            }\n            row:=privateP6Record{signedBatchIndex:joined.batchIndex,sourceBatchID:sourceBatchID,ordinal:ordinal,prepared:prepared,selectedSinglePass:selectedSinglePass,singlePassSecurity:singlePassSecurity}\n            if err:=p6.Add(ctx,row);err!=nil{return ordinal,fmt.Errorf(\"FI P6 typed family handoff: %w\",err)}\n            if readErr!=nil {\n                if errors.Is(readErr,io.EOF) {return ordinal,errors.New(\"FI P6: signed source ended without final LF\")}\n                return ordinal,readErr\n            }\n            continue\n        }\n        if prepared.Record.RecordKind != \"WindowsSecurityCoverage\" &&",
    },
    {
      "go/internal/recordingest/backlog_typed_window_postgres.go",
      "profile.coverageBuffer = newSecurityCoverageBulkState(&profile)",
      "profile.coverageBuffer = newSecurityCoverageBulkState(&profile)\n    var p6 *privateP6Buffers\n    if privateP6Selected() {\n        if !joined || !privateP5Enabled() || index<1 {return errors.New(\"FI P6: requires joined P5 private W512 typed window\")}\n        sink,sinkErr:=newPrivateP6SQLCoordinator(shadow,d.SourceID,&profile)\n        if sinkErr!=nil{return sinkErr}\n        p6,sinkErr=newPrivateP6Buffers(index,sink)\n        if sinkErr!=nil{return sinkErr}\n        ctx=context.WithValue(ctx,privateP6WindowContextKey{},p6)\n        fmt.Printf(\"FI P6 WINDOW START window=%d families=5 parent_ledger=ordered writer=1 atomic=true\\n\",index)\n    }",
    },
    {
      "go/internal/recordingest/backlog_typed_window_postgres.go",
      "joinedElapsed := time.Since(joinedStarted)",
      "joinedElapsed := time.Since(joinedStarted)\n    // Final family SQL buffers drain after joined-source timing closes.\n    if p6!=nil {\n        if err:=p6.Finish(ctx);err!=nil{return fmt.Errorf(\"FI P6: atomic W512 relational handoff barrier: %w\",err)}\n    }",
    },
    {
      "go/internal/recordingest/security_bulk.go",
      "copied, err := tx.CopyFrom(ctx, pgx.Identifier{\"fi\", \"source_record\"}, sourceColumns, sourceRows)",
      "var copied int64\n    var err error\n    if privateP6SourceAlreadyInserted(ctx) {\n        copied=int64(len(pending)) // parent already inserted in exact custody order\n    }else{\n        copied,err=tx.CopyFrom(ctx,pgx.Identifier{\"fi\",\"source_record\"},sourceColumns,sourceRows)\n    }",
    },
    // C1 only: P6 already mapped each Security parent by exact signed
    // (batch,ordinal). Do not perform the identical PostgreSQL lookup again.
    {
      "go/internal/recordingest/security_bulk.go",
      "ids, err := lookupBulkSourceRecordIDs(ctx, tx, batchIDs, ordinals)",
      "ids := privateC1KnownSourceIDs(ctx)\n    if len(ids)==0 {\n        ids,err=lookupBulkSourceRecordIDs(ctx,tx,batchIDs,ordinals)\n    }\n    if len(ids)!=len(pending) {return fmt.Errorf(\"FI C1: Security resolved source ID count mismatched\")}\n    for _,id:=range ids {if id<=0{return errors.New(\"FI C1: unresolved signed Security source FK\")}}",
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
  for _,n:=range []string{"private_canonical_spool_dispatch.go","private_canonical_spool_dispatch_test.go","private_header_first_p2.go","private_header_first_p2_test.go","private_family_preparation_p3.go","private_family_preparation_p3_test.go","private_family_dynamic_p4.go","private_family_dynamic_p4_test.go","private_family_persistent_p5.go","private_family_persistent_p5_test.go","private_p6_family_buffers.go","private_p6_family_buffers_test.go","private_p6_file_proof_test.go","private_p6_sql_coordinator.go","private_p6_sql_security.go","private_p6_sql_ntfs.go","private_p6_sql_coverage.go","private_p6_sql_usn.go","private_p6_sql_other.go"} {
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
  fmt.Printf("FI FAMILY P6 PRIVATE PATCH PASS source_files=%d modifications=%d readonly_spool=true families=5 source_ledger=ordered writer=1 atomic=true\n",len(files),len(edits))
}
func fail(err error){ fmt.Fprintln(os.Stderr,"FI FAMILY P3 PATCH STOP:",err);os.Exit(1) }
