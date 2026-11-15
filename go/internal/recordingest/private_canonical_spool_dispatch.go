// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Experimental, isolated header-first stream parser. No active H16 wiring.
package recordingest

import (
    "bytes"
    "context"
    "errors"
    "fmt"
    "io"
    "time"
)

type spoolDispatchFamily uint8

const (
    spoolDispatchSecurity spoolDispatchFamily = iota
    spoolDispatchFile
    spoolDispatchCoverage
    spoolDispatchUSN
    spoolDispatchOther
    spoolDispatchFamilyCount
)

var (
    canonicalSpoolKindPrefix = []byte("{\"version\":\"fi-spool-record/0.1\",\"record_kind\":\"")
    canonicalSpoolKindSuffix = []byte("\",\"scope_id\":")
)
const maxCanonicalRecordKindBytes = 64

// This is an exact, top-level canonical header check, not a JSON decoder.
// It must only be used on receiver-authenticated canonical spool input;
// existing noncanonical parsing remains available in the unchanged H16 path.
func classifyCanonicalSpoolRecord(raw []byte) (string, spoolDispatchFamily, error) {
    if !bytes.HasPrefix(raw, canonicalSpoolKindPrefix) {
        return "", 0, errors.New("FI header dispatch: noncanonical spool header")
    }
    tail := raw[len(canonicalSpoolKindPrefix):]
    limit := len(tail)
    if limit > maxCanonicalRecordKindBytes+1 { limit = maxCanonicalRecordKindBytes+1 }
    end := bytes.IndexByte(tail[:limit], '"')
    if end <= 0 || end > maxCanonicalRecordKindBytes ||
        !bytes.HasPrefix(tail[end:], canonicalSpoolKindSuffix) {
        return "", 0, errors.New("FI header dispatch: invalid record_kind field")
    }
    // All 13 accepted typed-window kinds have an explicit dispatch destination.
    switch string(tail[:end]) {
    case "WindowsSecurityEvent":
        return "WindowsSecurityEvent", spoolDispatchSecurity, nil
    case "WindowsSecurityContinuityGap":
        return "WindowsSecurityContinuityGap", spoolDispatchSecurity, nil
    case "FileObservation":
        return "FileObservation", spoolDispatchFile, nil
    case "WindowsSecurityCoverage":
        return "WindowsSecurityCoverage", spoolDispatchCoverage, nil
    case "USNReadBoundary":
        return "USNReadBoundary", spoolDispatchUSN, nil
    case "USNObjectObservation":
        return "USNObjectObservation", spoolDispatchUSN, nil
    case "USNContinuityGap":
        return "USNContinuityGap", spoolDispatchUSN, nil
    case "NTFSCollectionError":
        return "NTFSCollectionError", spoolDispatchOther, nil
    case "SupportingSourceCollectionError":
        return "SupportingSourceCollectionError", spoolDispatchOther, nil
    case "CollectorIdentity":
        return "CollectorIdentity", spoolDispatchOther, nil
    case "DirectoryPrincipalSnapshot":
        return "DirectoryPrincipalSnapshot", spoolDispatchOther, nil
    case "LocalPrincipalSnapshot":
        return "LocalPrincipalSnapshot", spoolDispatchOther, nil
    case "SMBShareSnapshot":
        return "SMBShareSnapshot", spoolDispatchOther, nil
    default:
        return "", 0, errors.New("FI header dispatch: unsupported canonical record_kind")
    }
}

type spoolBlockDispatchMetrics struct {
    ReadCalls uint64
    ReadTime time.Duration
    Records uint64
    Bytes uint64
    CrossBlockRecords uint64
    ByFamily [spoolDispatchFamilyCount]uint64
}

// Reads blocks, not individual lines; loops over complete JSONL records in
// memory. The consumer must finish using raw or copy any retained bytes before
// returning. The buffer is reused. Read boundaries do NOT flush SQL buffers.
// The dispatcher never parses payloads or changes transaction checkpoints.
func streamCanonicalSpoolBlocks(
    ctx context.Context, source io.Reader, blockBytes, maxRecordBytes int,
    consume func(raw []byte, kind string, family spoolDispatchFamily) error,
) (spoolBlockDispatchMetrics, error) {
    var metrics spoolBlockDispatchMetrics
    if ctx == nil || source == nil || consume == nil ||
        blockBytes <= 0 || maxRecordBytes <= 0 {
        return metrics, errors.New("FI block dispatch: invalid arguments")
    }
    block := make([]byte, blockBytes)
    var carry []byte
    zeroReads := 0

    dispatch := func(raw []byte, crossed bool) error {
        if len(raw) == 0 || raw[len(raw)-1] != '\n' ||
            len(raw) > maxRecordBytes {
            return fmt.Errorf("FI block dispatch: malformed or oversize ordinal %d", metrics.Records+1)
        }
        kind, family, err := classifyCanonicalSpoolRecord(raw)
        if err != nil {
            return fmt.Errorf("FI block dispatch: ordinal %d: %w", metrics.Records+1, err)
        }
        if err := consume(raw, kind, family); err != nil {
            return fmt.Errorf("FI block dispatch: ordinal %d kind=%s: %w", metrics.Records+1, kind, err)
        }
        metrics.Records++
        metrics.Bytes += uint64(len(raw))
        metrics.ByFamily[family]++
        if crossed { metrics.CrossBlockRecords++ }
        return nil
    }

    for {
        if err := ctx.Err(); err != nil { return metrics, err }
        readStarted := time.Now()
        n, readErr := source.Read(block)
        metrics.ReadTime += time.Since(readStarted)
        metrics.ReadCalls++
        if n < 0 || n > len(block) {
            return metrics, errors.New("FI block dispatch: invalid reader result")
        }
        if n == 0 && readErr == nil {
            zeroReads++
            if zeroReads >= 100 { return metrics, io.ErrNoProgress }
            continue
        }
        zeroReads = 0
        chunk := block[:n]
        for len(chunk) > 0 {
            if err := ctx.Err(); err != nil { return metrics, err }
            newline := bytes.IndexByte(chunk, '\n')
            if newline < 0 {
                if len(carry) > maxRecordBytes-len(chunk) {
                    return metrics, fmt.Errorf("FI block dispatch: record %d exceeds limit", metrics.Records+1)
                }
                carry = append(carry, chunk...)
                break
            }
            line := chunk[:newline+1]
            if len(carry) != 0 {
                if len(carry) > maxRecordBytes-len(line) {
                    return metrics, fmt.Errorf("FI block dispatch: record %d exceeds limit", metrics.Records+1)
                }
                carry = append(carry, line...)
                if err := dispatch(carry, true); err != nil { return metrics, err }
                carry = carry[:0]
            } else if err := dispatch(line, false); err != nil {
                return metrics, err
            }
            chunk = chunk[newline+1:]
        }
        if readErr != nil {
            if !errors.Is(readErr, io.EOF) {
                return metrics, fmt.Errorf("FI block dispatch: read: %w", readErr)
            }
            if len(carry) != 0 {
                return metrics, fmt.Errorf("FI block dispatch: missing final LF ordinal %d", metrics.Records+1)
            }
            return metrics, nil
        }
    }
}