// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Private-only, fail-closed H16 buffering correction. Run ONLY on a disposable
// historically pinned H16 archive, AFTER the mixed/dependency buffer patches.
// Never edit the live worktree, authoritative SoR or receiver.
package main

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

type sourceEdit struct {
    path string
    before string
    after string
}

var edits = []sourceEdit{
    {
        path:"go/internal/recordingest/private_mixed_family_buffers.go",
        before:`func validatePrivateFamilyRoute(ctx context.Context) error {`,
        after:`// Only the two EXACT reviewed source/child COPY profiles are permitted.
 // The private H16 hash writer deliberately changes the F3 profile name
 // from F3 to F3H16 AFTER mixed/dependency mode selection. A name-only F3
 // assertion in the per-batch route incorrectly rejected this valid mode.
 // Never accept arbitrary F3H16 limits or a different Security/USN route.
 func privateH16CombinedFileProfileValid(ctx context.Context) bool {
     got := fileBulkLimitsFromContext(ctx)
     f3 := fileBulkLimits{
         Name: "F3", SourceMaxRecords: 8192, SourceMaxBytes: 32 << 20,
         ObserveMaxRecords: 8192, ObserveMaxBytes: 32 << 20,
         HashMaxRows: 8192, HashMaxBytes: 8 << 20, ChildMaxRows: 4096,
     }
     if got == f3 { return true }
     f3.Name = "F3H16"
     f3.HashMaxRows = 16384
     f3.HashMaxBytes = 16 << 20
     return got == f3
 }
 func validatePrivateFamilyRoute(ctx context.Context) error {`,
    },
    {
        path:"go/internal/recordingest/private_mixed_family_buffers.go",
        before:`    if !usePrivateSinglePassSecurity(ctx) ||
        joinedBacklogChunkRecords(ctx) != 32768 ||
        fileBulkLimitsFromContext(ctx).Name != "F3" {
        return errors.New("FI PRIVATE BUFFER ROUTE STOP: private H16 profile context changed")`,
        after:`    if !usePrivateSinglePassSecurity(ctx) ||
        joinedBacklogChunkRecords(ctx) != 32768 ||
        !privateH16CombinedFileProfileValid(ctx) {
        return errors.New("FI PRIVATE BUFFER ROUTE STOP: private H16 Security/K32/File profile context changed")`,
    },
    {
        path:"go/internal/recordingest/backlog_typed_window_postgres.go",
        before:`backlogTypedChunkDirective{state: typedChunk, finish: finishChunk}`,
        after:`backlogTypedChunkDirective{state: typedChunk,
                    finish: h16FamilyDrainAtBoundary(ctx, finishChunk, offset+1 == len(batchIDs))}`,
    },
    {
        path:"go/internal/recordingest/backlog_typed_window_postgres.go",
        before:`		if finishChunk {
			if len(typedChunk.files) != 0 || len(typedChunk.security) != 0 ||
				len(typedChunk.dependencies) != 0 || typedChunk.dependencyBytes != 0 ||
				len(typedChunk.fileBulk.records) != 0 || typedChunk.filesBytes() != 0 {
				return errors.New("FI typed chunk: buffers remained after required flush")
			}
			chunkSamples = append(chunkSamples, backlogTypedChunkSample{`,
        after:`        if finishChunk {
            // The private H16 candidate retains Security/File/USN buffers
            // between K32 work units in the SAME original W128 transaction.
            // The final signed batch MUST drain them before W128 commit.
            if h16FamilyDrainAtBoundary(ctx, finishChunk, offset+1 == len(batchIDs)) &&
                (len(typedChunk.files) != 0 || len(typedChunk.security) != 0 ||
                    len(typedChunk.dependencies) != 0 || typedChunk.dependencyBytes != 0 ||
                    len(typedChunk.fileBulk.records) != 0 || typedChunk.filesBytes() != 0) {
                return errors.New("FI H16 combined buffers: pending rows after required W128 drain")
            }
            chunkSamples = append(chunkSamples, backlogTypedChunkSample{`,
    },
    {
        path:"go/internal/recordingest/backlog_typed_window_postgres.go",
        before:`fmt.Printf("FI PRIVATE BUFFER ROUTE WINDOW START window=%d joined=%t K32=%d dependency_mode=true\n", index, joined, chunkLimit)`,
        after:`fmt.Printf("FI PRIVATE BUFFER ROUTE WINDOW START window=%d joined=%t K32=%d dependency_mode=true\n", index, joined, chunkLimit)
        fmt.Printf("FI PRIVATE H16 COMBINED BUFFER ROUTE window=%d K32=32768 k32_partial_flushes=0 W128_atomic=true source=original_H16\n", index)`,
    },
}

const drainFunction = `
// h16FamilyDrainAtBoundary keeps the original single W128 SQL transaction
// and K32 work-unit telemetry. Only the explicit private dependency-buffer
// candidate suppresses premature partial family flushes at K32 boundaries.
// The final W128 signed batch still drains all pending typed children BEFORE
// the unchanged atomic typed checkpoint; cross-W128 carry is not claimed.
func h16FamilyDrainAtBoundary(ctx context.Context, k32Finished, lastWindowBatch bool) bool {
    if !privateDependencyBuffersEnabled(ctx) {
        return k32Finished
    }
    return lastWindowBatch
}
`

func main() {
    if len(os.Args)!=2 || !filepath.IsAbs(os.Args[1]) {
        fmt.Fprintln(os.Stderr,"FI H16 COMBINED PATCH STOP: absolute disposable source directory required")
        os.Exit(1)
    }
    root:=os.Args[1]
    originals:=map[string]string{}
    modified:=map[string]string{}
    for i, edit:=range edits {
        absolute:=filepath.Join(root,filepath.Clean(edit.path))
        src,found:=modified[absolute]
        if !found {
            raw,err:=os.ReadFile(absolute)
            if err!=nil {fmt.Fprintln(os.Stderr,"FI H16 COMBINED PATCH STOP:",err);os.Exit(1)}
            src=string(raw)
            originals[absolute]=src
        }
        if n:=strings.Count(src,edit.before);n!=1 {
            fmt.Fprintf(os.Stderr,"FI H16 COMBINED PATCH STOP: edit=%d anchor_count=%d file=%s\n",i,n,edit.path)
            os.Exit(1)
        }
        modified[absolute]=strings.Replace(src,edit.before,edit.after,1)
    }
    chunkPath:=filepath.Join(root,"go/internal/recordingest/backlog_typed_chunks.go")
    original,err:=os.ReadFile(chunkPath)
    if err!=nil {fmt.Fprintln(os.Stderr,"FI H16 COMBINED PATCH STOP:",err);os.Exit(1)}
    if strings.Contains(string(original),"func h16FamilyDrainAtBoundary(") ||
        !strings.Contains(string(original),"func shouldFinishBacklogTypedChunk(") {
        fmt.Fprintln(os.Stderr,"FI H16 COMBINED PATCH STOP: unexpected historical K32 scheduler")
        os.Exit(1)
    }
    if _,exists:=modified[chunkPath];exists {
        panic(errors.New("unexpected overlapping H16 combined source patches"))
    }
    originals[chunkPath]=string(original)
    modified[chunkPath]=string(original)+drainFunction
    // Validate every exact anchor before making any on-disk changes.
    for path,patched:=range modified {
        if _,ok:=originals[path];!ok{panic("source inventory missing")}
        if err:=os.WriteFile(path,[]byte(patched),0600);err!=nil {
            fmt.Fprintln(os.Stderr,"FI H16 COMBINED PATCH STOP:",err)
            os.Exit(1)
        }
    }
    fmt.Printf("FI H16 COMBINED BUFFER PATCH PASS files=%d edits=%d H16_sql_window_unchanged=true\n",
        len(modified),len(edits))
}
