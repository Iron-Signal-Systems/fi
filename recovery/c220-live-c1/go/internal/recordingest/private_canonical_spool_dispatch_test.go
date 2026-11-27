// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "bytes"
    "context"
    "errors"
    "io"
    "strings"
    "testing"
)

func canonicalDispatchFixture(kind, payload string) []byte {
    return []byte("{\"version\":\"fi-spool-record/0.1\",\"record_kind\":\"" +
        kind + "\",\"scope_id\":\"s\",\"written_at\":\"2026-11-15T00:00:00Z\",\"payload\":" + payload + "}\n")
}

func TestCanonicalDispatchAllSupportedKinds(t *testing.T) {
    cases := []struct { kind string; family spoolDispatchFamily }{
        {"WindowsSecurityEvent", spoolDispatchSecurity},
        {"WindowsSecurityContinuityGap", spoolDispatchSecurity},
        {"FileObservation", spoolDispatchFile},
        {"WindowsSecurityCoverage", spoolDispatchCoverage},
        {"USNReadBoundary", spoolDispatchUSN},
        {"USNObjectObservation", spoolDispatchUSN},
        {"USNContinuityGap", spoolDispatchUSN},
        {"NTFSCollectionError", spoolDispatchOther},
        {"SupportingSourceCollectionError", spoolDispatchOther},
        {"CollectorIdentity", spoolDispatchOther},
        {"DirectoryPrincipalSnapshot", spoolDispatchOther},
        {"LocalPrincipalSnapshot", spoolDispatchOther},
        {"SMBShareSnapshot", spoolDispatchOther},
    }
    for _, tc := range cases {
        t.Run(tc.kind, func(t *testing.T) {
            // Deliberately malformed payload is irrelevant to routing.
            kind, family, err := classifyCanonicalSpoolRecord(canonicalDispatchFixture(tc.kind, "!!"))
            if err != nil || kind != tc.kind || family != tc.family {
                t.Fatalf("kind=%q family=%d err=%v", kind, family, err)
            }
        })
    }
}

func TestCanonicalDispatchRejectsNoncanonicalOrUnknownKinds(t *testing.T) {
    cases := [][]byte{
        []byte("{\"record_kind\":\"WindowsSecurityEvent\",\"version\":\"fi-spool-record/0.1\",\"scope_id\":\"s\"}\n"),
        []byte("{\"version\":\"bad\",\"record_kind\":\"WindowsSecurityEvent\",\"scope_id\":\"s\"}\n"),
        []byte("{\"version\":\"fi-spool-record/0.1\",\"record_kind\":\"WindowsSecurityEvent\",\"payload\":{\"scope_id\":\"s\"}}\n"),
        canonicalDispatchFixture("NotSupported", "{}"),
        canonicalDispatchFixture(strings.Repeat("A", 65), "{}"),
    }
    for i, raw := range cases {
        if _, _, err := classifyCanonicalSpoolRecord(raw); err == nil {
            t.Fatalf("case %d accepted invalid header", i)
        }
    }
}

func TestCanonicalDispatchBlockSplitsPreserveEveryByte(t *testing.T) {
    kinds := []string{"WindowsSecurityEvent", "FileObservation", "WindowsSecurityCoverage", "USNObjectObservation", "CollectorIdentity"}
    var expected [][]byte
    var data []byte
    for i, kind := range kinds {
        line := canonicalDispatchFixture(kind, "{\"n\":\""+strings.Repeat("a", 31*i+7)+"\"}")
        expected = append(expected, line)
        data = append(data, line...)
    }
    for _, blockSize := range []int{1, 3, 17, 63, 4096, len(data)+1} {
        seen := make([][]byte, 0, len(expected))
        stats, err := streamCanonicalSpoolBlocks(context.Background(), bytes.NewReader(data),
            blockSize, 4096, func(raw []byte, kind string, family spoolDispatchFamily) error {
                if kind != kinds[len(seen)] { t.Fatalf("kind %q at index %d", kind, len(seen)) }
                // Only the test retains data; the streaming callback normally
                // turns the record into SQL-ready owned values.
                seen = append(seen, bytes.Clone(raw))
                return nil
            })
        if err != nil { t.Fatalf("block=%d: %v", blockSize, err) }
        if stats.Records != uint64(len(expected)) || stats.Bytes != uint64(len(data)) {
            t.Fatalf("block=%d: stats=%+v", blockSize, stats)
        }
        for i := range seen {
            if !bytes.Equal(seen[i], expected[i]) {
                t.Fatalf("block=%d record=%d changed", blockSize, i)
            }
        }
        if blockSize == 1 && stats.CrossBlockRecords != uint64(len(expected)) {
            t.Fatalf("cross-block tracking failed: %+v", stats)
        }
    }
}

func TestCanonicalDispatchRejectsIncompleteAndOversize(t *testing.T) {
    line := canonicalDispatchFixture("FileObservation", "{}")
    for _, tc := range []struct{name string; data []byte; max int}{
        {"oversize", line, len(line)-1},
        {"missingLF", bytes.TrimSuffix(line, []byte("\n")), 4096},
    } {
        t.Run(tc.name, func(t *testing.T) {
            _, err := streamCanonicalSpoolBlocks(context.Background(), bytes.NewReader(tc.data),
                7, tc.max, func(raw []byte, kind string, family spoolDispatchFamily) error {
                    t.Fatal("unacceptable record dispatched")
                    return nil
                })
            if err == nil { t.Fatal("expected error") }
        })
    }
}

func TestCanonicalDispatchPropagatesCallbackErrorAndCancel(t *testing.T) {
    line := canonicalDispatchFixture("WindowsSecurityEvent", "{}")
    sentinel := errors.New("processor failed")
    stats, err := streamCanonicalSpoolBlocks(context.Background(), bytes.NewReader(line),
        1024, 1024, func([]byte, string, spoolDispatchFamily) error { return sentinel })
    if !errors.Is(err, sentinel) || stats.Records != 0 {
        t.Fatalf("err=%v stats=%+v", err, stats)
    }
    ctx, cancel := context.WithCancel(context.Background())
    cancel()
    _, err = streamCanonicalSpoolBlocks(ctx, bytes.NewReader(line),
        1024, 1024, func([]byte, string, spoolDispatchFamily) error { t.Fatal("cancelled callback"); return nil })
    if !errors.Is(err, context.Canceled) { t.Fatalf("err=%v", err) }
}

func TestCanonicalDispatchEOFAndReadError(t *testing.T) {
    stats, err := streamCanonicalSpoolBlocks(context.Background(), strings.NewReader(""),
        32, 1024, func([]byte, string, spoolDispatchFamily) error { return nil })
    if err != nil || stats.Records != 0 { t.Fatalf("err=%v stats=%+v", err, stats) }
    line := canonicalDispatchFixture("FileObservation", "{}")
    stats, err = streamCanonicalSpoolBlocks(context.Background(), &dispatchTestFailReader{data:line},
        4096, 4096, func([]byte, string, spoolDispatchFamily) error { return nil })
    if !errors.Is(err, io.ErrUnexpectedEOF) || stats.Records != 1 {
        t.Fatalf("err=%v stats=%+v", err, stats)
    }
}

type dispatchTestFailReader struct { data []byte; read bool }
func (r *dispatchTestFailReader) Read(p []byte) (int, error) {
    if r.read { return 0, io.ErrUnexpectedEOF }
    r.read = true
    return copy(p, r.data), io.ErrUnexpectedEOF
}
