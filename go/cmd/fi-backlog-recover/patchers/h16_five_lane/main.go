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
    {path:"go/cmd/fi-backlog-recover/main_freebsd.go",before:"var privateMixedBuffers, privateDependencyBuffers, privateContinuousFamily bool",after:"var privateMixedBuffers, privateDependencyBuffers, privateContinuousFamily bool\n\tvar privateH16FiveLane bool"},
    {path:"go/cmd/fi-backlog-recover/main_freebsd.go",before:"flag.BoolVar(&privateDependencyBuffers, \"private-dependency-buffers\", false, \"DEV ONLY: isolate Security coverage and USN capture/dependencies from Security/File flushes\")",after:"flag.BoolVar(&privateDependencyBuffers, \"private-dependency-buffers\", false, \"DEV ONLY: isolate Security coverage and USN capture/dependencies from Security/File flushes\")\n\tflag.BoolVar(&privateH16FiveLane, \"private-h16-five-lane\", false, \"DEV ONLY: independently drain File source and File projection with Security/coverage/USN in isolated original-H16 W128\")"},
    {path:"go/cmd/fi-backlog-recover/main_freebsd.go",before:"if privateDependencyBuffers && !privateMixedBuffers {\n\t\treturn errors.New(\"FI private dependency buffers require private mixed-family buffer mode\")\n\t}",after:"if privateDependencyBuffers && !privateMixedBuffers {\n\t\treturn errors.New(\"FI private dependency buffers require private mixed-family buffer mode\")\n\t}\n\tif privateH16FiveLane && (!privateMixedBuffers || !privateDependencyBuffers ||\n\t\t!enable || !continuousPrivate || !privateFieldPartitions ||\n\t\twindowProfile != \"W128\" || processingChunkRecords != 32768 ||\n\t\tsecurityProfile != \"P3\" || fileProfile != \"F3\" || verifiedCacheRoot == \"\" ||\n\t\tstartWindow != 3 || maxWindows != 0 || indexedPrivate ||\n\t\tstreamLoader || preflightOnly || privateContinuousFamily) {\n\t\treturn errors.New(\"FI private five-lane coordinator requires exact disposable W128/K32/P3/F3 signed-cache dependency-buffer profile\")\n\t}"},
    {path:"go/cmd/fi-backlog-recover/main_freebsd.go",before:"fmt.Println(\"FI PRIVATE DEPENDENCY BUFFERS ENABLED independent_coverage=true ordered_usn=true\")",after:"fmt.Println(\"FI PRIVATE DEPENDENCY BUFFERS ENABLED independent_coverage=true ordered_usn=true\")\n\t\t\tif privateH16FiveLane {\n\t\t\t\tctx, profileErr = recordingest.WithPrivateH16FiveLaneCoordinator(ctx)\n\t\t\t\tif profileErr != nil {\n\t\t\t\t\treturn profileErr\n\t\t\t\t}\n\t\t\t\tfmt.Println(\"FI PRIVATE FIVE LANE ENABLED source=joined_signed Security=bounded File_source=bounded File_projection=bounded Coverage=bounded USN=ordered W128_atomic=true\")\n\t\t\t}"},
    {path:"go/internal/recordingest/postgres_ingest.go",before:"if err := fileBulk.flush(ctx, tx); err != nil {\n\t\t\treturn fmt.Errorf(\"%w: batch %s FileObservation projection records %d-%d: %v\", ErrSourceRecordRejected, batch.BatchID, first, last, err)\n\t\t}\n\t\tpendingFiles = nil",after:"// With the five-lane coordinator, source COPY completion does not force a\n\t\t// partially filled File projection lane to drain. add() already\n\t\t// enforces independent record/byte bounds; no payload is copied.\n\t\tif !privateH16FiveLaneDeferProjectionAfterSource(ctx) {\n\t\t\tif err := fileBulk.flush(ctx, tx); err != nil {\n\t\t\t\treturn fmt.Errorf(\"%w: batch %s FileObservation projection records %d-%d: %v\", ErrSourceRecordRejected, batch.BatchID, first, last, err)\n\t\t\t}\n\t\t} else if stats := privateH16FiveLaneStats(ctx); stats != nil {\n\t\t\tstats.FileSourceDrains++\n\t\t\tif len(fileBulk.records) != 0 {\n\t\t\t\tstats.DeferredFileProjection++\n\t\t\t}\n\t\t}\n\t\tpendingFiles = nil"},
    {path:"go/internal/recordingest/postgres_ingest.go",before:"// prerequisite work here; unrelated Security/coverage are NOT.\n\t\tif err := flushFiles(); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif err := flushPrivateDependencies(ctx, tx, sourceID, pendingDependencies, profile); err != nil {",after:"// prerequisite work here; unrelated Security/coverage are NOT.\n\t\tif err := flushFiles(); err != nil {\n\t\t\treturn err\n\t\t}\n\t\t// A queued USN boundary/object may resolve File/NTFS parents. The\n\t\t// source lane alone is insufficient: force the File projection\n\t\t// lane to complete before the original ordered USN projector.\n\t\tif privateH16FiveLaneEnabled(ctx) && len(fileBulk.records) != 0 {\n\t\t\tif err := fileBulk.flush(ctx, tx); err != nil {\n\t\t\t\treturn fmt.Errorf(\"%w: five-lane File projection prerequisite for USN: %v\", ErrSourceRecordRejected, err)\n\t\t\t}\n\t\t\tif stats := privateH16FiveLaneStats(ctx); stats != nil {\n\t\t\t\tstats.DependencyProjectionDrains++\n\t\t\t}\n\t\t}\n\t\tif err := flushPrivateDependencies(ctx, tx, sourceID, pendingDependencies, profile); err != nil {"},
    {path:"go/internal/recordingest/postgres_ingest.go",before:"if privateDependencyBuffersEnabled(ctx) && decision.security && decision.files {\n\t\t\tif err := flushDependencies(); err != nil {\n\t\t\t\treturn ordinal, err\n\t\t\t}\n\t\t}\n\t\tif prepared.Record.RecordKind == \"WindowsSecurityEvent\" {",after:"if privateDependencyBuffersEnabled(ctx) && decision.security && decision.files {\n\t\t\tif err := flushDependencies(); err != nil {\n\t\t\t\treturn ordinal, err\n\t\t\t}\n\t\t}\n\t\t// Unknown/unaudited kinds remain a hard relational ordering fence.\n\t\t// The fifth File projection lane must also drain, even when there\n\t\t// are no pending USN dependencies.\n\t\tif privateH16FiveLaneEnabled(ctx) &&\n\t\t\tprivateH16FiveLaneOrderingFence(prepared.Record.RecordKind) &&\n\t\t\tlen(fileBulk.records) != 0 {\n\t\t\tif err := fileBulk.flush(ctx, tx); err != nil {\n\t\t\t\treturn ordinal, fmt.Errorf(\"%w: five-lane ordering File projection: %v\", ErrSourceRecordRejected, err)\n\t\t\t}\n\t\t\tif stats := privateH16FiveLaneStats(ctx); stats != nil {\n\t\t\t\tstats.OrderingProjectionDrains++\n\t\t\t}\n\t\t}\n\t\tif prepared.Record.RecordKind == \"WindowsSecurityEvent\" {"},
    {path:"go/internal/recordingest/postgres_ingest.go",before:"fileFlushStarted := time.Now()\n\t\tfileFlushErr := fileBulk.flush(ctx, tx)",after:"fileFlushStarted := time.Now()\n\t\tif privateH16FiveLaneEnabled(ctx) && len(fileBulk.records) != 0 {\n\t\t\tif stats := privateH16FiveLaneStats(ctx); stats != nil {\n\t\t\t\tstats.FinalProjectionDrains++\n\t\t\t}\n\t\t}\n\t\tfileFlushErr := fileBulk.flush(ctx, tx)"},
    {path:"go/internal/recordingest/backlog_typed_window_postgres.go",before:"ctx = context.WithValue(ctx, backlogUSNCrossWindowContextKey{}, true)",after:"ctx = context.WithValue(ctx, backlogUSNCrossWindowContextKey{}, true)\n\tif privateH16FiveLaneEnabled(ctx) {\n\t\tctx = context.WithValue(ctx, privateH16FiveLaneTelemetryKey{}, &privateH16FiveLaneTelemetry{})\n\t}"},
    {path:"go/internal/recordingest/backlog_typed_window_postgres.go",before:"for i, chunk := range chunkSamples {\n\t\tfmt.Printf(\"FI TYPED CHUNK COMMITTED",after:"if privateH16FiveLaneEnabled(ctx) {\n\t\tstats := privateH16FiveLaneStats(ctx)\n\t\tif stats != nil {\n\t\t\tfmt.Printf(\"FI PRIVATE FIVE LANE PROOF window=%d file_source_drains=%d deferred_file_projection=%d usn_projection_fences=%d ordering_projection_fences=%d final_projection_drains=%d W128_atomic=true\\n\",\n\t\t\t\tindex, stats.FileSourceDrains, stats.DeferredFileProjection, stats.DependencyProjectionDrains, stats.OrderingProjectionDrains, stats.FinalProjectionDrains)\n\t\t}\n\t}\n\tfor i, chunk := range chunkSamples {\n\t\tfmt.Printf(\"FI TYPED CHUNK COMMITTED"},
}
func main() {
    if len(os.Args)!=2 || !filepath.IsAbs(os.Args[1]) {
        fmt.Fprintln(os.Stderr,"FI PRIVATE FIVE LANE PATCH STOP: absolute disposable source path required")
        os.Exit(1)
    }
    root:=filepath.Clean(os.Args[1])
    if !strings.HasPrefix(root,"/home/jwood/fi-window-bench-") && !strings.HasPrefix(root,"/tmp/fi-window-bench-") {
        fmt.Fprintln(os.Stderr,"FI PRIVATE FIVE LANE PATCH STOP: unapproved disposable source root")
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
            fmt.Fprintf(os.Stderr,"FI PRIVATE FIVE LANE PATCH STOP edit=%d anchor_count=%d file=%s\n",i,n,edit.path)
            os.Exit(1)
        }
        updated[full]=strings.Replace(data,edit.before,edit.after,1)
    }
    // Validate assets and edits BEFORE modifying any existing source file.
    for _,name:=range []string{"private_h16_five_lane.go","private_h16_five_lane_test.go"} {
        asset:=filepath.Join(root,"go/cmd/fi-backlog-recover/testdata/h16-five-lane",name)
        if _,err:=os.Stat(asset);err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(1)}
        target:=filepath.Join(root,"go/internal/recordingest",name)
        if _,err:=os.Stat(target);err==nil {
            fmt.Fprintln(os.Stderr,"FI PRIVATE FIVE LANE PATCH STOP: old five-lane file already present",name)
            os.Exit(1)
        }
    }
    for full,data:=range updated {
        if err:=os.WriteFile(full,[]byte(data),0600);err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(1)}
    }
    for _,name:=range []string{"private_h16_five_lane.go","private_h16_five_lane_test.go"} {
        asset:=filepath.Join(root,"go/cmd/fi-backlog-recover/testdata/h16-five-lane",name)
        target:=filepath.Join(root,"go/internal/recordingest",name)
        b,err:=os.ReadFile(asset)
        if err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(1)}
        if err:=os.WriteFile(target,b,0600);err!=nil {fmt.Fprintln(os.Stderr,err);os.Exit(1)}
    }
    fmt.Printf("FI PRIVATE FIVE LANE PATCH PASS edits=%d files=%d new_bounded_family_lane=File_projection original_W128_sql=true\n",len(edits),len(updated))
}
