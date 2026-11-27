// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Historical-H16-only five-lane processing overlay. All edits use exact
// anchors; any unexpected revision is rejected BEFORE this can be benchmarked.
package main

import (
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

type sourceEdit struct { path, before, after string }
var edits=[]sourceEdit{
    {path:"go/cmd/fi-backlog-recover/main_freebsd.go",before:"var optimizedK32 bool",after:"var optimizedK32 bool\n\tvar privateParallelA bool"},
    {path:"go/cmd/fi-backlog-recover/main_freebsd.go",before:"flag.BoolVar(&privateDependencyBuffers, \"private-dependency-buffers\", false, \"DEV ONLY: independently buffer coverage and USN capture/dependency records\")",after:"flag.BoolVar(&privateDependencyBuffers, \"private-dependency-buffers\", false, \"DEV ONLY: independently buffer coverage and USN capture/dependency records\")\n\tflag.BoolVar(&privateParallelA, \"private-parallel-prep-a\", false, \"DEV ONLY: two pure preparation workers, one ordered H16 combined-buffer PostgreSQL writer\")"},
    {path:"go/cmd/fi-backlog-recover/main_freebsd.go",before:"if privateDependencyBuffers && !privateMixedBuffers {\n\t\treturn errors.New(\"FI private dependency buffers require mixed-family private mode\")\n\t}",after:"if privateDependencyBuffers && !privateMixedBuffers {\n\t\treturn errors.New(\"FI private dependency buffers require mixed-family private mode\")\n\t}\n\tif privateParallelA && (!privateMixedBuffers || !privateDependencyBuffers ||\n\t\t!enable || !continuousPrivate || !privateFieldPartitions ||\n\t\twindowProfile != \"W128\" || processingChunkRecords != 32768 ||\n\t\tsecurityProfile != \"P3\" || fileProfile != \"F3\" || verifiedCacheRoot == \"\" ||\n\t\tstartWindow != 3 || maxWindows != 0 || indexedPrivate ||\n\t\tstreamLoader || preflightOnly) {\n\t\treturn errors.New(\"FI candidate A requires exact disposable W128/K32/P3/F3 verified signed-cache combined buffer mode\")\n\t}"},
    {path:"go/cmd/fi-backlog-recover/main_freebsd.go",before:"fmt.Println(\"FI PRIVATE DEPENDENCY BUFFERS ENABLED independent_coverage=true ordered_usn=true\")",after:"fmt.Println(\"FI PRIVATE DEPENDENCY BUFFERS ENABLED independent_coverage=true ordered_usn=true\")\n\t\t\tif privateParallelA {\n\t\t\t\tctx, profileErr = recordingest.WithPrivateParallelPreparationA(ctx)\n\t\t\t\tif profileErr != nil {\n\t\t\t\t\treturn profileErr\n\t\t\t\t}\n\t\t\t\tfmt.Println(\"FI PRIVATE PARALLEL PREP A ENABLED workers=2 inflight=4 postgres_writers=1 W128_atomic=true\")\n\t\t\t}"},
    {path:"go/internal/recordingest/postgres_ingest.go",before:"reader := bufio.NewReader(file)",after:"reader := bufio.NewReader(file)\n\t// Candidate A overlaps immutable source decoding with the unchanged\n\t// combined-buffer SQL writer. Cancellation joins all goroutines before\n\t// the signed batch file is closed on any failure.\n\tvar parallelPrep *privateParallelPreparedStream\n\t// Fail before processing this batch if CLI requested Candidate A but\n\t// context/profiles unexpectedly disabled it. Never publish an ordinary\n\t// sequential replay as a successful parallel preparation trial.\n\tif err := privateParallelAActivationError(ctx); err != nil {\n\t\treturn 0, fmt.Errorf(\"%w: %v\", ErrSourceRecordRejected, err)\n\t}\n\tif privateParallelARequested(ctx) {\n\t\tparallelPrep, err = newPrivateParallelPreparedStream(ctx, reader, privateParallelAPrepare)\n\t\tif err != nil {\n\t\t\treturn 0, fmt.Errorf(\"FI candidate A: start bounded pure preparation: %w\", err)\n\t\t}\n\t\tdefer parallelPrep.Close()\n\t}"},
    {path:"go/internal/recordingest/postgres_ingest.go",before:"readStarted := time.Now()\n\t\traw, readErr := reader.ReadBytes('\\n')\n\t\tprofile.Read += time.Since(readStarted)",after:"var raw []byte\n\t\tvar readErr error\n\t\tvar parallelLine privateParallelLine\n\t\tif parallelPrep != nil {\n\t\t\tvar ok bool\n\t\t\tparallelLine, ok = parallelPrep.Next()\n\t\t\tif !ok { break }\n\t\t\traw, readErr = parallelLine.raw, parallelLine.readErr\n\t\t\tprofile.Read += parallelLine.readTime\n\t\t} else {\n\t\t\treadStarted := time.Now()\n\t\t\traw, readErr = reader.ReadBytes('\\n')\n\t\t\tprofile.Read += time.Since(readStarted)\n\t\t}"},
    {path:"go/internal/recordingest/postgres_ingest.go",before:"prepareStarted := time.Now()\n\t\tvar prepared SourceRecord\n\t\tvar singlePassSecurity securityBulkRecord\n\t\tvar selectedSinglePass bool\n\t\tvar prepareErr error\n\t\tif usePrivateSinglePassSecurity(ctx) {\n\t\t\tprepared, singlePassSecurity, selectedSinglePass, prepareErr = tryPrepareSinglePassSecurity(raw)\n\t\t}\n\t\tif prepareErr == nil && !selectedSinglePass {\n\t\t\tprepared, prepareErr = prepareOwnedSourceRecord(raw)\n\t\t}\n\t\t// For canonical Security events the outer envelope and typed payload\n\t\t// are decoded and validated ONCE. This timer includes both operations,\n\t\t// so no second Security preparation time is counted for fast-path rows.\n\t\tprofile.Prepare += time.Since(prepareStarted)",after:"var prepared SourceRecord\n\t\tvar singlePassSecurity securityBulkRecord\n\t\tvar selectedSinglePass bool\n\t\tvar prepareErr error\n\t\tif parallelPrep != nil {\n\t\t\t// Only preparation was moved to workers. All source hashes,\n\t\t\t// joined-source custody, buffer routing and SQL remain ordered\n\t\t\t// in the original transaction-owning goroutine.\n\t\t\tprepared, singlePassSecurity = parallelLine.source, parallelLine.security\n\t\t\tselectedSinglePass, prepareErr = parallelLine.selected, parallelLine.prepareErr\n\t\t\tprofile.Prepare += parallelLine.prepareTime\n\t\t} else {\n\t\t\tprepareStarted := time.Now()\n\t\t\tif usePrivateSinglePassSecurity(ctx) {\n\t\t\t\tprepared, singlePassSecurity, selectedSinglePass, prepareErr = tryPrepareSinglePassSecurity(raw)\n\t\t\t}\n\t\t\tif prepareErr == nil && !selectedSinglePass {\n\t\t\t\tprepared, prepareErr = prepareOwnedSourceRecord(raw)\n\t\t\t}\n\t\t\t// Historical single-writer preparation timing unchanged.\n\t\t\tprofile.Prepare += time.Since(prepareStarted)\n\t\t}"},
    {path:"go/internal/recordingest/postgres_ingest.go",before:"\treturn ordinal, nil\n}\n\nfunc verifyGenerationProjectionCoverage",after:"\tif parallelPrep != nil {\n\t\tif parallelPrep.rows != ordinal {\n\t\t\treturn ordinal, errors.New(\"FI candidate A: prepared source count differs from signed manifest\")\n\t\t}\n\t\t// These are independent, overlapping durations: worker time is the\n\t\t// sum of CPU-facing preparation periods, not elapsed transaction time.\n\t\tfmt.Printf(\"FI PRIVATE PARALLEL PREP BATCH batch=%s workers=2 inflight_limit=4 writers=1 records=%d read=%s worker_prepare=%s writer_wait=%s reordered=%d reorder_peak=%d\\n\",\n\t\t\tbatch.BatchID, parallelPrep.rows, parallelPrep.readerTime, parallelPrep.workerTime,\n\t\t\tparallelPrep.waits, parallelPrep.reordered, parallelPrep.peakReorder)\n\t}\n\treturn ordinal, nil\n}\n\nfunc verifyGenerationProjectionCoverage"},
}
func main() {
    if len(os.Args)!=2 || !filepath.IsAbs(os.Args[1]) {
        fmt.Fprintln(os.Stderr,"FI PRIVATE PARALLEL PREP A PATCH STOP: absolute disposable source path required")
        os.Exit(1)
    }
    root:=filepath.Clean(os.Args[1])
    if !strings.HasPrefix(root,"/home/jwood/fi-window-bench-") && !strings.HasPrefix(root,"/tmp/fi-window-bench-") {
        fmt.Fprintln(os.Stderr,"FI PRIVATE PARALLEL PREP A PATCH STOP: unapproved disposable source root")
        os.Exit(1)
    }
    updated:=map[string]string{}
    for i,edit:=range edits {
        full:=filepath.Join(root,edit.path)
        data,ok:=updated[full]
        if !ok {
            b,err:=os.ReadFile(full)
            if err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(1)}
            data=string(b)
        }
        if n:=strings.Count(data,edit.before);n!=1 {
            fmt.Fprintf(os.Stderr,"FI PRIVATE PARALLEL PREP A PATCH STOP edit=%d anchor_count=%d file=%s\n",i,n,edit.path)
            os.Exit(1)
        }
        updated[full]=strings.Replace(data,edit.before,edit.after,1)
    }
    // Validate assets and edits BEFORE modifying any existing source file.
    for _,name:=range []string{"private_parallel_preparation.go","private_parallel_preparation_test.go"} {
        asset:=filepath.Join(root,"go/cmd/fi-backlog-recover/testdata/h16-parallel-a",name)
        if _,err:=os.Stat(asset);err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(1)}
        target:=filepath.Join(root,"go/internal/recordingest",name)
        if _,err:=os.Stat(target);err==nil {
            fmt.Fprintln(os.Stderr,"FI PRIVATE PARALLEL PREP A PATCH STOP: old candidate A private file already present",name)
            os.Exit(1)
        }
    }
    for full,data:=range updated {
        if err:=os.WriteFile(full,[]byte(data),0600);err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(1)}
    }
    for _,name:=range []string{"private_parallel_preparation.go","private_parallel_preparation_test.go"} {
        asset:=filepath.Join(root,"go/cmd/fi-backlog-recover/testdata/h16-parallel-a",name)
        target:=filepath.Join(root,"go/internal/recordingest",name)
        b,err:=os.ReadFile(asset)
        if err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(1)}
        if err:=os.WriteFile(target,b,0600);err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(1)}
    }
    fmt.Printf("FI PRIVATE PARALLEL PREP A PATCH PASS edits=%d files=%d preparation_workers=2 max_inflight_records=4 postgres_writers=1 W128_atomic=true original_W128_sql=true\n",len(edits),len(updated))
}
