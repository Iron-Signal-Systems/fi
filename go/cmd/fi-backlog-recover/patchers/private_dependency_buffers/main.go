// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Apply exact, fail-closed private dependency-buffer edits ONLY to the staged
// historical H16+SHA-once+JSON-once+mixed-family disposable source archive.
// Each old anchor must occur exactly once; never patch a real live worktree.
package main

import (
  "fmt"
  "os"
  "path/filepath"
  "strings"
)

type patch struct { path, before, after string }

var changes = []patch{
{"go/internal/recordingest/postgres_ingest.go", "\t\tif err := flushSecurity(); err != nil {\n\t\t\treturn ordinal, err\n\t\t}", "\t\tif err := flushSecurity(); err != nil {\n\t\t\treturn ordinal, err\n\t\t}\n\t\tif err := flushDependencies(); err != nil {\n\t\t\treturn ordinal, err\n\t\t}"},
{"go/internal/recordingest/postgres_ingest.go", "\t\tcontiguousSecurity = 0", "\t\tcontiguousSecurity = 0\n\t\tif privateDependencyBuffersEnabled(ctx) &&\n\t\t\tprivateUSNDependentKind(prepared.Record.RecordKind) {\n\t\t\tincoming := int64(prepared.RecordBytes)\n\t\t\tif privateDependencyShouldFlushBefore(len(pendingDependencies), pendingDependencyBytes, incoming) {\n\t\t\t\tif err := flushDependencies(); err != nil {\n\t\t\t\t\treturn ordinal, err\n\t\t\t\t}\n\t\t\t}\n\t\t\tjoined := joinedBacklogSourceFromContext(ctx)\n\t\t\tif joined == nil || joined.batchIndex < 0 {\n\t\t\t\treturn ordinal, errors.New(\"FI private dependency: original signed batch index is unavailable\")\n\t\t\t}\n\t\t\tvar queueErr error\n\t\t\tpendingDependencies, pendingDependencyBytes, queueErr =\n\t\t\t\tprivateDependencyAppend(pendingDependencies, pendingDependencyBytes,\n\t\t\t\t\tsourceBatchID, joined.batchIndex, ordinal, prepared)\n\t\t\tif queueErr != nil {\n\t\t\t\treturn ordinal, queueErr\n\t\t\t}\n\t\t\tif pendingDependencyBytes > privateDependencyMaxBytes {\n\t\t\t\tif err := flushDependencies(); err != nil {\n\t\t\t\t\treturn ordinal, err\n\t\t\t\t}\n\t\t\t}\n\t\t\tif readErr != nil {\n\t\t\t\tif errors.Is(readErr, io.EOF) {\n\t\t\t\t\treturn ordinal, fmt.Errorf(\"%w: batch %s ended without final LF\", ErrSourceRecordRejected, batch.BatchID)\n\t\t\t\t}\n\t\t\t\treturn ordinal, fmt.Errorf(\"read FI source batch: %w\", readErr)\n\t\t\t}\n\t\t\tcontinue\n\t\t}"},
{"go/internal/recordingest/postgres_ingest.go", "\t\tdecision := securityFileFlushBeforeKind(ctx, prepared.Record.RecordKind)", "\t\tif privateDependencyBuffersEnabled(ctx) &&\n\t\t\tprepared.Record.RecordKind == \"WindowsSecurityCoverage\" &&\n\t\t\tlen(pendingSecurity) != 0 {\n\t\t\tprofile.PrivateCoverageSecurityFencesAvoided++\n\t\t}\n\t\tdecision := securityFileFlushBeforeKind(ctx, prepared.Record.RecordKind)"},
{"go/internal/recordingest/postgres_ingest.go", "\t\tif prepared.Record.RecordKind != \"WindowsSecurityCoverage\" {", "\t\tif prepared.Record.RecordKind != \"WindowsSecurityCoverage\" &&\n\t\t\t!privateDependencyBuffersEnabled(ctx) {"},
{"go/internal/recordingest/postgres_ingest.go", "\t\tpendingSecurityBytes = 0\n\t\treturn nil\n\t}", "\t\tpendingSecurityBytes = 0\n\t\treturn nil\n\t}\n\tflushDependencies := func() error {\n\t\tif len(pendingDependencies) == 0 {\n\t\t\treturn nil\n\t\t}\n\t\t// The USN projector may resolve NTFS identities. File writes are\n\t\t// prerequisite work here; unrelated Security/coverage are NOT.\n\t\tif err := flushFiles(); err != nil {\n\t\t\treturn err\n\t\t}\n\t\tif err := flushPrivateDependencies(ctx, tx, sourceID, pendingDependencies, profile); err != nil {\n\t\t\treturn fmt.Errorf(\"%w: batch %s USN dependency COPY: %v\",\n\t\t\t\tErrSourceRecordRejected, batch.BatchID, err)\n\t\t}\n\t\tpendingDependencies = nil\n\t\tpendingDependencyBytes = 0\n\t\treturn nil\n\t}"},
{"go/internal/recordingest/postgres_ingest.go", "\t\t\tchunk.state.files, chunk.state.fileBytes = pendingFiles, pendingFileBytes", "\t\t\tchunk.state.files, chunk.state.fileBytes = pendingFiles, pendingFileBytes\n\t\t\tchunk.state.dependencies, chunk.state.dependencyBytes = pendingDependencies, pendingDependencyBytes"},
{"go/internal/recordingest/postgres_ingest.go", "\t\tfileBulk = chunk.state.fileBulk", "\t\tfileBulk = chunk.state.fileBulk\n\t\tpendingDependencies = chunk.state.dependencies\n\t\tpendingDependencyBytes = chunk.state.dependencyBytes"},
{"go/internal/recordingest/postgres_ingest.go", "\tvar pendingFileBytes int64", "\tvar pendingFileBytes int64\n\t// A third, independently bounded family queues USN capture boundaries and\n\t// dependent objects in original signed order inside the same K32 chunk.\n\tvar pendingDependencies []privateDependencySourceRecord\n\tvar pendingDependencyBytes int64"},
{"go/internal/recordingest/postgres_ingest.go", "\tSinglePassSecurityRows int64 // private-P3 canonical Security decode only", "\tSinglePassSecurityRows int64 // private-P3 canonical Security decode only\n\tPrivateDependencyFlushes int64 // private-only bounded USN queue flushes\n\tPrivateDependencyRows int64 // source-bound USN boundaries and objects written\n\tPrivateCoverageSecurityFencesAvoided int64 // coverage arrivals that formerly flushed pending Security"},
{"go/internal/recordingest/backlog_typed_chunks.go", "    fileBulk *fileObservationBulkState", "    fileBulk *fileObservationBulkState\n    dependencies []privateDependencySourceRecord\n    dependencyBytes int64"},
{"go/internal/recordingest/backlog_typed_window_postgres.go", "\t\t\tjoinedSource.copyTime.Round(time.Millisecond), joinedSource.verifyTime.Round(time.Millisecond))\n\t}", "\t\t\tjoinedSource.copyTime.Round(time.Millisecond), joinedSource.verifyTime.Round(time.Millisecond))\n\t}\n\tif ctx.Value(privateDependencyBuffersKey{}) == true {\n\t\tfmt.Printf(\"FI PRIVATE DEPENDENCY BUFFER PROOF window=%d dependency_records=%d dependency_flushes=%d coverage_security_flushes_avoided=%d security_source_copy_calls=%d security_event_copy_calls=%d\\n\",\n\t\t\tindex, profile.PrivateDependencyRows, profile.PrivateDependencyFlushes,\n\t\t\tprofile.PrivateCoverageSecurityFencesAvoided,\n\t\t\tprofile.SecurityBulk.SourceLatency.Calls, profile.SecurityBulk.EventLatency.Calls)\n\t}"},
{"go/internal/recordingest/backlog_typed_window_postgres.go", "\t\t\tif len(typedChunk.files) != 0 || len(typedChunk.security) != 0 ||", "\t\t\tif len(typedChunk.files) != 0 || len(typedChunk.security) != 0 ||\n\t\t\t\tlen(typedChunk.dependencies) != 0 || typedChunk.dependencyBytes != 0 ||"},
{"go/cmd/fi-backlog-recover/main_freebsd.go", "\tvar privateMixedBuffers bool\n", "\tvar privateMixedBuffers bool\n\tvar privateDependencyBuffers bool\n"},
{"go/cmd/fi-backlog-recover/main_freebsd.go", "\tflag.BoolVar(&privateMixedBuffers, \"private-mixed-family-buffers\", false, \"DEV ONLY: separate Security/File buffers within W128/K32; preserve other-family ordering fences\")\n", "\tflag.BoolVar(&privateMixedBuffers, \"private-mixed-family-buffers\", false, \"DEV ONLY: separate Security/File buffers within W128/K32; preserve other-family ordering fences\")\n\tflag.BoolVar(&privateDependencyBuffers, \"private-dependency-buffers\", false, \"DEV ONLY: independently buffer coverage and USN capture/dependency records\")\n"},
{"go/cmd/fi-backlog-recover/main_freebsd.go", "\tif privateMixedBuffers {\n", "\tif privateDependencyBuffers && !privateMixedBuffers {\n\t\treturn errors.New(\"FI private dependency buffers require mixed-family private mode\")\n\t}\n\tif privateMixedBuffers {\n"},
{"go/cmd/fi-backlog-recover/main_freebsd.go", "\t\tfmt.Println(\"FI PRIVATE MIXED FAMILY BUFFERS ENABLED k32=true security_p3=true file_f3=true dependent_kinds=fenced\")\n", "\t\tfmt.Println(\"FI PRIVATE MIXED FAMILY BUFFERS ENABLED k32=true security_p3=true file_f3=true dependent_kinds=fenced\")\n\t\tif privateDependencyBuffers {\n\t\t\tctx, profileErr = recordingest.WithPrivateDependencyBuffers(ctx)\n\t\t\tif profileErr != nil {\n\t\t\t\treturn profileErr\n\t\t\t}\n\t\t\tfmt.Println(\"FI PRIVATE DEPENDENCY BUFFERS ENABLED independent_coverage=true ordered_usn=true\")\n\t\t}\n"},
{"go/internal/recordingest/postgres_ingest.go", "\t\tif decision.files {\n\t\t\tif err := flushFiles(); err != nil {\n\t\t\t\treturn ordinal, err\n\t\t\t}\n\t\t}\n\t\tif prepared.Record.RecordKind == \"WindowsSecurityEvent\" {", "\t\tif decision.files {\n\t\t\tif err := flushFiles(); err != nil {\n\t\t\t\treturn ordinal, err\n\t\t\t}\n\t\t}\n\t\t// Any remaining, unaudited record family is a strict source-order\n\t\t// fence for queued USN dependencies.\n\t\tif privateDependencyBuffersEnabled(ctx) && decision.security && decision.files {\n\t\t\tif err := flushDependencies(); err != nil {\n\t\t\t\treturn ordinal, err\n\t\t\t}\n\t\t}\n\t\tif prepared.Record.RecordKind == \"WindowsSecurityEvent\" {"},

{"go/internal/recordingest/postgres_ingest.go", "\tif hasChunk {\n\t\tif chunk.state == nil || chunk.state.fileBulk == nil {\n\t\t\treturn 0, errors.New(\"FI typed chunk: invalid shared buffer\")\n\t\t}\n\t\tpendingSecurity = chunk.state.security", "\tif err := validatePrivateFamilyRoute(ctx); err != nil {\n\t\treturn 0, err\n\t}\n\tif hasChunk {\n\t\tif chunk.state == nil || chunk.state.fileBulk == nil {\n\t\t\treturn 0, errors.New(\"FI typed chunk: invalid shared buffer\")\n\t\t}\n\t\tpendingSecurity = chunk.state.security"},

{"go/internal/recordingest/postgres_ingest.go", "\t\tif err := flushFiles(); err != nil {\n\t\t\treturn ordinal, err\n\t\t}", "\t\tif err := flushFiles(); err != nil {\n\t\t\treturn ordinal, err\n\t\t}\n\t\tif privateDependencyBuffersEnabled(ctx) && len(pendingSecurity) != 0 {\n\t\t\tprofile.PrivateSecurityBoundaryFlushes++\n\t\t}"},
{"go/internal/recordingest/postgres_ingest.go", "\t\t\t) {", "\t\t\t) {\n\t\t\t\tif privateDependencyBuffersEnabled(ctx) && len(pendingSecurity) != 0 {\n\t\t\t\t\tprofile.PrivateSecurityCapacityFlushes++\n\t\t\t\t}"},
{"go/internal/recordingest/postgres_ingest.go", "\t\tif decision.security {", "\t\tif decision.security {\n\t\t\tif privateDependencyBuffersEnabled(ctx) && len(pendingSecurity) != 0 {\n\t\t\t\tprofile.PrivateSecurityBarrierFlushes++\n\t\t\t}"},
{"go/internal/recordingest/postgres_ingest.go", "\tPrivateCoverageSecurityFencesAvoided int64 // coverage arrivals that formerly flushed pending Security", "\tPrivateCoverageSecurityFencesAvoided int64 // coverage arrivals that formerly flushed pending Security\n\tPrivateSecurityCapacityFlushes int64 // P3 reached its own record or byte cap\n\tPrivateSecurityBoundaryFlushes int64 // trial-only K32/W128 end drains\n\tPrivateSecurityBarrierFlushes int64 // conservative unaudited kind"},
{"go/internal/recordingest/backlog_typed_window_postgres.go", "\t\t\tprofile.SecurityBulk.SourceLatency.Calls, profile.SecurityBulk.EventLatency.Calls)", "\t\t\tprofile.SecurityBulk.SourceLatency.Calls, profile.SecurityBulk.EventLatency.Calls,\n\t\t\tprofile.PrivateSecurityCapacityFlushes,\n\t\t\tprofile.PrivateSecurityBoundaryFlushes,\n\t\t\tprofile.PrivateSecurityBarrierFlushes)"},
{"go/internal/recordingest/backlog_typed_window_postgres.go", "\t\tfmt.Printf(\"FI PRIVATE DEPENDENCY BUFFER PROOF window=%d dependency_records=%d dependency_flushes=%d coverage_security_flushes_avoided=%d security_source_copy_calls=%d security_event_copy_calls=%d\\n\",", "\t\tfmt.Printf(\"FI PRIVATE DEPENDENCY BUFFER PROOF window=%d dependency_records=%d dependency_flushes=%d coverage_security_flushes_avoided=%d security_source_copy_calls=%d security_event_copy_calls=%d security_capacity_flushes=%d security_boundary_flushes=%d security_barrier_flushes=%d\\n\","},
{"go/internal/recordingest/backlog_typed_window_postgres.go", "\tchunkLimit := joinedBacklogChunkRecords(ctx)", "\tchunkLimit := joinedBacklogChunkRecords(ctx)\n\tif ctx.Value(privateDependencyBuffersKey{}) == true {\n\t\tif !joined || chunkLimit != 32768 || !privateMixedFamilyBuffersEnabled(ctx) {\n\t\t\treturn errors.New(\"FI PRIVATE BUFFER ROUTE STOP: W128/K32 source and family configuration invalid\")\n\t\t}\n\t\tfmt.Printf(\"FI PRIVATE BUFFER ROUTE WINDOW START window=%d joined=%t K32=%d dependency_mode=true\\n\", index, joined, chunkLimit)\n\t}"},

}

func main() {
    if len(os.Args) != 2 || !filepath.IsAbs(os.Args[1]) {
        fmt.Fprintln(os.Stderr, "FI DEPENDENCY PATCH STOP: absolute disposable source root required")
        os.Exit(1)
    }
    root := os.Args[1]
    originals := make(map[string]string)
    modified := make(map[string]string)
    for i, p := range changes {
        filepathRel := filepath.Clean(p.path)
        full := filepath.Join(root, filepathRel)
        current, ok := modified[full]
        if !ok {
            body, err := os.ReadFile(full)
            if err != nil { fmt.Fprintf(os.Stderr, "FI DEPENDENCY PATCH STOP: %v\n", err); os.Exit(1) }
            current = string(body)
            originals[full] = current
        }
        if strings.Count(current, p.before) != 1 {
            fmt.Fprintf(os.Stderr, "FI DEPENDENCY PATCH STOP: missing/nonunique anchor step=%d file=%s\n", i, p.path)
            os.Exit(1)
        }
        modified[full] = strings.Replace(current, p.before, p.after, 1)
    }
    // Validate every patch before writing ANY file; all edits remain inside
    // the disposable source archive, with no canonical writes.
    for full, body := range modified {
        if _, ok := originals[full]; !ok { panic("source inventory corrupted") }
        if err := os.WriteFile(full, []byte(body), 0600); err != nil {
            fmt.Fprintf(os.Stderr, "FI DEPENDENCY PATCH STOP: write %s: %v\n", full, err)
            os.Exit(1)
        }
    }
    fmt.Printf("FI PRIVATE DEPENDENCY PATCH PASS files=%d edits=%d private_only=true usn_ordered=true coverage_independent=true\n", len(modified), len(changes))
}
