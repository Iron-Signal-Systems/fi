//go:build freebsd

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// FI DEVELOPMENT ONLY. This tool authenticates one historical FIGT generation
// and creates a receipt-bound private benchmark cache. NO SQL or live ingestion.
package main

import (
    "errors"
    "fmt"
    "os"

    "github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

const (
    sourceID = "iss-fs-22a.iss.local"
    generationID = "20261030T000032.061323100Z-3e38b2210771462c"
    expectedBatches = 8399
    expectedRecords = 15140785
    expectedW512Windows = 31
    expectedSeedRecords = 493478
    expectedSeedDigest = "ff58478b40ca35f1f6cc5e52aa0300de6371ed58243c41f34e4f20ad6d61a319"
    cacheRoot = "/home/jwood/fi-w512-c220-verified-cache"
)

func run() (retErr error) {
    config := recordingest.GenerationLoadConfig{
        CustodyRoot: "/var/db/fi/custody/generation",
        RecordedRoot: "/var/db/fi/custody/recorded",
        MaxCanonicalBytes: 68719476736,
        MaxEncodedBytes: 68719476736,
        MaxManifestBytes: 1048576,
        SourceNamespaces: false,
        SourceID: sourceID,
    }
    // The historical authenticated loader is W128-bounded; its full signed
    // scan and receipt-bound publication can be reused by the W512 planner.
    w128 := recordingest.BacklogWindowLimits{
        MaxRecords: 131072,
        MaxDataBytes: 1 << 30,
    }
    w512 := recordingest.BacklogWindowLimits{
        MaxRecords: 524288,
        MaxDataBytes: 2 << 30,
    }
    fmt.Printf("FI C220 CACHE: source=%s generation=%s\n", sourceID, generationID)
    fmt.Println("FI C220 CACHE: authenticating full signed custody; no PostgreSQL")
    g, err := recordingest.LoadRecordedGenerationSelectedWindowsCached(
        config, generationID, w128, 0, 1, cacheRoot,
        func(p recordingest.BacklogStreamProgress) {
            if p.BatchesSeen%256 == 0 {
                fmt.Printf("FI C220 CACHE PROGRESS batches=%d/%d records=%d/%d data_bytes=%d\n",
                    p.BatchesSeen, expectedBatches, p.RecordsSeen, expectedRecords, p.DataBytesSeen)
            }
        },
    )
    if err != nil {
        return fmt.Errorf("authenticated full custody cache rejected: %w", err)
    }
    defer func() {
        if closeErr := g.Close(); closeErr != nil {
            retErr = errors.Join(retErr, fmt.Errorf("private staging cleanup: %w", closeErr))
        }
    }()
    if len(g.Batches) != expectedBatches ||
        g.Receipt.BatchCount != expectedBatches ||
        g.Receipt.RecordCount != expectedRecords {
        return fmt.Errorf("signed totals mismatch: batches=%d/%d records=%d/%d",
            len(g.Batches), expectedBatches, g.Receipt.RecordCount, expectedRecords)
    }
    windows, err := recordingest.DescribeBacklogWindows(g, w512)
    if err != nil {
        return fmt.Errorf("signed W512 window descriptors: %w", err)
    }
    if len(windows) != expectedW512Windows ||
        windows[0].EndRecord != expectedSeedRecords ||
        windows[0].DigestSHA256 != expectedSeedDigest {
        return fmt.Errorf("historical W512 checkpoint mismatch: windows=%d seed_records=%d seed_digest=%s",
            len(windows), windows[0].EndRecord, windows[0].DigestSHA256)
    }
    for i, d := range windows {
        if i > 10 { break }
        fmt.Printf("FI W512 PLANNED index=%d batch_range=%d..%d record_range=%d..%d digest=%s\n",
            i, d.StartBatch, d.EndBatch, d.StartRecord, d.EndRecord, d.DigestSHA256)
    }
    fmt.Printf("FI C220 SIGNED CACHE AND W512 PLAN PASS batches=%d records=%d windows=%d seed_records=%d seed_digest=%s authoritative_writes=0 accepted_writes=0\n",
        len(g.Batches), g.Receipt.RecordCount, len(windows), windows[0].EndRecord, windows[0].DigestSHA256)
    return nil
}

func main() {
    if len(os.Args) != 1 {
        fmt.Fprintln(os.Stderr, "arguments forbidden")
        os.Exit(2)
    }
    if err := run(); err != nil {
        fmt.Fprintln(os.Stderr, "FI C220 PRIVATE CACHE STOP:", err)
        os.Exit(1)
    }
}
