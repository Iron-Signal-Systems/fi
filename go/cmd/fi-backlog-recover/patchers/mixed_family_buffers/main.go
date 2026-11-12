// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Applies the *exact* private mixed-family experiment to the disposable
// historically pinned H16/SHA-once source clone. Fails if an anchor moves.
// Does not modify any repository worktree, production binary, or database.
package main

import (
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
)

type replacement struct {
    old string
    new string
}
type sourcePatch struct {
    relative string
    replace []replacement
}

func applySourcePatch(root string, p sourcePatch) error {
    path := filepath.Join(root, p.relative)
    raw, err := os.ReadFile(path)
    if err != nil {
        return err
    }
    body := string(raw)
    for i, r := range p.replace {
        if strings.Count(body, r.old) != 1 {
            return fmt.Errorf("%s: expected exactly one source anchor at step %d", p.relative, i)
        }
        body = strings.Replace(body, r.old, r.new, 1)
    }
    if err := os.WriteFile(path, []byte(body), 0600); err != nil {
        return err
    }
    return nil
}

func main() {
    if len(os.Args) != 2 || !filepath.IsAbs(os.Args[1]) {
        fmt.Fprintln(os.Stderr, "FI MIXED BUFFER PATCH STOP: absolute disposable source root required")
        os.Exit(1)
    }
    root := os.Args[1]
    // Deliberately patch only three ingest files and the private test CLI.
    // The archival source was previously pinned and SHA-once already applied.
    patches := []sourcePatch{
        {
            relative: "go/internal/recordingest/postgres_ingest.go",
            replace: []replacement{
                {
                    old: `		if prepared.Record.RecordKind == "WindowsSecurityEvent" {
			contiguousSecurity++
			if contiguousSecurity > profile.SecurityBulk.MaxContiguousSecurity {
				profile.SecurityBulk.MaxContiguousSecurity = contiguousSecurity
			}
			if err := flushFiles(); err != nil {
				return ordinal, err
			}
`,
                    new: `		if prepared.Record.RecordKind == "WindowsSecurityEvent" {
			contiguousSecurity++
			if contiguousSecurity > profile.SecurityBulk.MaxContiguousSecurity {
				profile.SecurityBulk.MaxContiguousSecurity = contiguousSecurity
			}
`,
                },
                {
                    old: `		contiguousSecurity = 0
		if err := flushSecurity(); err != nil {
			return ordinal, err
		}
		if prepared.Record.RecordKind == "FileObservation" || prepared.Record.RecordKind == "USNObjectObservation" {`,
                    new: `		contiguousSecurity = 0
		if prepared.Record.RecordKind == "FileObservation" || prepared.Record.RecordKind == "USNObjectObservation" {`,
                },
                {
                    old: `		if err := flushFiles(); err != nil {
			return ordinal, err
		}
		var sourceRecordID int64`,
                    new: `		var sourceRecordID int64`,
                },
                {
                    old: `		if prepared.Record.RecordKind != "WindowsSecurityCoverage" {
			if err := profile.coverageBuffer.flush(ctx, tx); err != nil {
				return ordinal, fmt.Errorf("%w: batch %s Security coverage COPY: %v", ErrSourceRecordRejected, batch.BatchID, err)
			}
		}`,
                    new: `		if prepared.Record.RecordKind != "WindowsSecurityCoverage" {
			if err := profile.coverageBuffer.flush(ctx, tx); err != nil {
				return ordinal, fmt.Errorf("%w: batch %s Security coverage COPY: %v", ErrSourceRecordRejected, batch.BatchID, err)
			}
		}
		// Private W128/K32 may retain bounded Security and File buffers
		// across their mutual transitions. All remaining record families
		// still flush both buffers before executing their projections.
		decision := securityFileFlushBeforeKind(ctx, prepared.Record.RecordKind)
		if decision.security {
			if err := flushSecurity(); err != nil {
				return ordinal, err
			}
		}
		if decision.files {
			if err := flushFiles(); err != nil {
				return ordinal, err
			}
		}`,
                },
            },
        },
        {
            relative: "go/internal/recordingest/backlog_typed_chunks.go",
            replace: []replacement{
                {
                    old: `    single := true
    for _, batchID := range batchIDs[1:] {
        if batchID != batchIDs[0] { single = false; break }
    }
    ids := make([]int64, len(batchIDs))
    if single {`,
                    new: `    // Independent family buffers contain gaps in one signed batch.
    // Use the ordinal BETWEEN fast lookup only for truly contiguous rows.
    single := bulkSourceIDsAreContiguousSingleBatch(batchIDs, ordinals)
    ids := make([]int64, len(batchIDs))
    if single {`,
                },
            },
        },
        {
            relative: "go/internal/recordingest/file_source_bulk.go",
            replace: []replacement{
                {
                    old: `(i > 0 && batchID == previousBatch && item.ordinal != pending[i-1].ordinal+1)`,
                    new: `(i > 0 && batchID == previousBatch &&
            fileOrdinalInvalidForBatch(ctx, item.ordinal, pending[i-1].ordinal))`,
                },
            },
        },
        {
            relative: "go/cmd/fi-backlog-recover/main_freebsd.go",
            replace: []replacement{
                {
                    old: `	var deferredVerifiedClone bool
	flag.BoolVar(&deferredVerifiedClone, "deferred-verified-clone", false,`,
                    new: `	var deferredVerifiedClone bool
	var privateMixedBuffers bool
	flag.BoolVar(&privateMixedBuffers, "private-mixed-family-buffers", false, "DEV ONLY: separate Security/File buffers within W128/K32; preserve other-family ordering fences")
	flag.BoolVar(&deferredVerifiedClone, "deferred-verified-clone", false,`,
                },
                {
                    old: `	ctx, profileErr = recordingest.WithFixedFileBulkProfile(ctx, fileProfile)
	if profileErr != nil {
		return profileErr
	}
	if privateHashH16 {`,
                    new: `	ctx, profileErr = recordingest.WithFixedFileBulkProfile(ctx, fileProfile)
	if profileErr != nil {
		return profileErr
	}
	if privateMixedBuffers {
		if !enable || !continuousPrivate || !privateFieldPartitions || !deferredVerifiedClone ||
			windowProfile != "W128" || processingChunkRecords != 32768 ||
			securityProfile != "P3" || fileProfile != "F3" ||
			verifiedCacheRoot == "" || startWindow != 3 || maxWindows != 0 ||
			indexedPrivate || streamLoader || preflightOnly {
			return errors.New("FI mixed buffers require exact isolated W128/K32/P3/F3 signed-cache private replay")
		}
		ctx, profileErr = recordingest.WithPrivateMixedFamilyBuffers(ctx)
		if profileErr != nil {
			return profileErr
		}
		fmt.Println("FI PRIVATE MIXED FAMILY BUFFERS ENABLED k32=true security_p3=true file_f3=true dependent_kinds=fenced")
	}
	if privateHashH16 {`,
                },
            },
        },
    }
    if len(patches) != 4 {
        panic(errors.New("FI mixed buffer patch inventory changed"))
    }
    for _, patch := range patches {
        if err := applySourcePatch(root, patch); err != nil {
            fmt.Fprintf(os.Stderr, "FI MIXED BUFFER PATCH STOP: %v\n", err)
            os.Exit(1)
        }
    }
    fmt.Println("FI MIXED BUFFER PATCH PASS private_only=true active_source=true sparse_ids=true usn_barriers=true")
}
