// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Behavioral tests for the CONTINUOUS routing state machine. These use a
// controlled fake sink, not PostgreSQL: SQL acceptance is a separate gate.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
)

type privateContinuousSinkProbe struct {
    durable map[int]bool
    flushes map[privateContinuousFamily]int
    committed []privateContinuousRecord
    projected []int
    failFamily privateContinuousFamily
}

func newPrivateContinuousSinkProbe() *privateContinuousSinkProbe {
    return &privateContinuousSinkProbe{
        durable: make(map[int]bool),
        flushes: make(map[privateContinuousFamily]int),
    }
}
func (s *privateContinuousSinkProbe) SourceWindowDurable(_ context.Context, i int) error {
    if !s.durable[i] {
        return fmt.Errorf("source marker %d missing", i)
    }
    return nil
}
func (s *privateContinuousSinkProbe) FlushFamily(_ context.Context, family privateContinuousFamily, rows []privateContinuousRecord) error {
    if family == s.failFamily {
        return errors.New("injected SQL transaction failure")
    }
    for _, row := range rows {
        if !s.durable[row.WindowIndex] {
            return errors.New("attempted SQL commit before source window durable")
        }
    }
    s.flushes[family]++
    s.committed = append(s.committed, rows...)
    return nil
}
func (s *privateContinuousSinkProbe) MarkProjected(_ context.Context, window int) error {
    s.projected = append(s.projected, window)
    return nil
}

func privateContinuousFixture(window, batch int, ordinal int64, kind string, size int) privateContinuousRecord {
    return privateContinuousRecord{
        WindowIndex: window,
        SignedBatchIndex: batch,
        Ordinal: ordinal,
        SourceBatchID: int64(batch+100),
        Prepared: SourceRecord{
            Record: spool.Record{RecordKind: kind}, RecordBytes: size,
        },
    }
}

func TestPrivateContinuousFamiliesDoNotFlushAtK32OrW128(t *testing.T) {
    ctx := context.Background()
    probe := newPrivateContinuousSinkProbe()
    probe.durable[3] = true
    probe.durable[4] = true
    router, err := newPrivateContinuousFamilyRouter(ctx, probe, 2)
    if err != nil { t.Fatal(err) }
    if err := router.BeginSourceWindow(ctx, 3); err != nil { t.Fatal(err) }
    for i, kind := range []string{"WindowsSecurityEvent", "FileObservation",
        "WindowsSecurityCoverage", "WindowsSecurityEvent", "FileObservation"} {
        if err := router.Add(ctx, privateContinuousFixture(3, 114, int64(i+1), kind, 240)); err != nil {
            t.Fatal(err)
        }
    }
    if err := router.EndSourceWindow(ctx, 3); err != nil { t.Fatal(err) }
    if len(probe.committed) != 0 || len(probe.projected) != 0 {
        t.Fatal("W128 boundary caused a premature flush or typed marker")
    }
    if err := router.BeginSourceWindow(ctx, 4); err != nil { t.Fatal(err) }
    for i, kind := range []string{"WindowsSecurityEvent", "USNReadBoundary",
        "USNObjectObservation", "WindowsSecurityCoverage", "FileObservation"} {
        if err := router.Add(ctx, privateContinuousFixture(4, 172, int64(i+1), kind, 320)); err != nil {
            t.Fatal(err)
        }
    }
    if err := router.EndSourceWindow(ctx, 4); err != nil { t.Fatal(err) }
    if len(probe.committed) != 0 || len(probe.projected) != 0 {
        t.Fatal("second W128 boundary flushed independent buffers")
    }
    if err := router.EndOfInput(ctx); err != nil { t.Fatal(err) }
    if len(probe.committed) != 10 || len(probe.projected) != 2 ||
        probe.projected[0] != 3 || probe.projected[1] != 4 ||
        probe.flushes[privateFamilySecurity] != 1 ||
        probe.flushes[privateFamilyFile] != 1 ||
        probe.flushes[privateFamilyCoverage] != 1 ||
        probe.flushes[privateFamilyUSN] != 1 {
        t.Fatalf("incorrect end-of-input drains committed=%d markers=%v flushes=%v",
            len(probe.committed), probe.projected, probe.flushes)
    }
}

func TestPrivateContinuousSecurityCapacityFlushCanCrossWindows(t *testing.T) {
    ctx := context.Background()
    probe := newPrivateContinuousSinkProbe()
    probe.durable[3] = true
    probe.durable[4] = true
    router, err := newPrivateContinuousFamilyRouter(ctx, probe, 2)
    if err != nil { t.Fatal(err) }
    if err := router.BeginSourceWindow(ctx, 3); err != nil { t.Fatal(err) }
    for i:=1; i<=2000; i++ {
        if err := router.Add(ctx, privateContinuousFixture(3, 110, int64(i),
            "WindowsSecurityEvent", 256)); err != nil { t.Fatal(err) }
    }
    if err := router.EndSourceWindow(ctx, 3); err != nil { t.Fatal(err) }
    if err := router.BeginSourceWindow(ctx, 4); err != nil { t.Fatal(err) }
    for i:=1; i<=2097; i++ {
        if err := router.Add(ctx, privateContinuousFixture(4, 150, int64(i),
            "WindowsSecurityEvent", 256)); err != nil { t.Fatal(err) }
    }
    if probe.flushes[privateFamilySecurity] != 1 ||
        len(probe.committed) != 4096 ||
        len(probe.projected) != 1 || probe.projected[0] != 3 {
        t.Fatalf("the 4096th Security event must flush, not W128: commits=%d flushes=%v projected=%v",
            len(probe.committed),probe.flushes,probe.projected)
    }
    if err := router.EndSourceWindow(ctx, 4); err != nil { t.Fatal(err) }
    if err := router.EndOfInput(ctx); err != nil { t.Fatal(err) }
    if len(probe.committed)!=4097 || len(probe.projected)!=2 ||
        probe.flushes[privateFamilySecurity]!=2 {
        t.Fatal("end-of-input did not close remaining Security event and W4 marker")
    }
}

func TestPrivateContinuousFailsClosedOnUndurableSourceAndBadOrder(t *testing.T) {
    ctx := context.Background()
    probe := newPrivateContinuousSinkProbe()
    router, err := newPrivateContinuousFamilyRouter(ctx, probe, 2)
    if err != nil { t.Fatal(err) }
    if err := router.BeginSourceWindow(ctx, 3); err == nil {
        t.Fatal("undurable source window accepted")
    }
    if err := router.Add(ctx, privateContinuousFixture(3, 110, 1, "WindowsSecurityEvent", 128)); err == nil {
        t.Fatal("source record accepted before durable window start")
    }
    probe.durable[3] = true
    if err := router.BeginSourceWindow(ctx, 3); err != nil { t.Fatal(err) }
    first := privateContinuousFixture(3, 110, 1, "WindowsSecurityEvent", 128)
    if err := router.Add(ctx, first); err != nil { t.Fatal(err) }
    if err := router.Add(ctx, first); err == nil {
        t.Fatal("duplicate signed ordinal accepted")
    }
    if err := router.Add(ctx, privateContinuousFixture(3, 109, 4, "FileObservation", 128)); err == nil {
        t.Fatal("reversed signed batch accepted")
    }
    if err := router.Add(ctx, privateContinuousFixture(3, 110, 2, "UnrecognizedRecordKind", 128)); err == nil {
        t.Fatal("unreviewed record family accepted")
    }
    if err := router.EndOfInput(ctx); err == nil {
        t.Fatal("end-of-input accepted an unclosed source window")
    }
}

func TestPrivateContinuousSQLFailureRetainsPendingRows(t *testing.T) {
    ctx := context.Background()
    probe := newPrivateContinuousSinkProbe()
    probe.durable[3] = true
    router, err := newPrivateContinuousFamilyRouter(ctx, probe, 2)
    if err != nil { t.Fatal(err) }
    if err := router.BeginSourceWindow(ctx, 3); err != nil { t.Fatal(err) }
    if err := router.Add(ctx, privateContinuousFixture(3, 110, 1, "WindowsSecurityEvent", 128)); err != nil {
        t.Fatal(err)
    }
    if err := router.EndSourceWindow(ctx, 3); err != nil { t.Fatal(err) }
    probe.failFamily = privateFamilySecurity
    if err := router.EndOfInput(ctx); err == nil {
        t.Fatal("failed SQL flush allowed typed marker or finish")
    }
    if len(router.lanes[privateFamilySecurity].pending) != 1 ||
        router.outstanding[3] != 1 || len(probe.projected) != 0 {
        t.Fatal("SQL error discarded uncommitted record or published marker")
    }
    probe.failFamily = 0
    if err := router.EndOfInput(ctx); err != nil { t.Fatal(err) }
    if len(probe.committed) != 1 || len(probe.projected) != 1 {
        t.Fatal("SQL retry did not durably complete source and projection")
    }
}

func TestPrivateContinuousEverySupportedKindHasAnExplicitLane(t *testing.T) {
    for kind := range supportedRecordKinds {
        family, err := privateFamilyForRecordKind(kind)
        if err != nil || family == 0 || family > privateFamilyOrderedOther {
            t.Fatalf("supported record kind %q has no bounded lane: family=%s err=%v", kind, family, err)
        }
    }
    if _, err := privateFamilyForRecordKind("Unknown"); err == nil {
        t.Fatal("unknown record kind silently routed")
    }
}

/*
Exact-limit regression: the capacity write must happen upon receipt of the
limit-filling record, not upon a later record or a K32/W128 boundary. It
exercises both independent threshold types and protects the durable-projection
contract when the final record of a source window happens to fill a buffer.
*/
func TestPrivateContinuousFlushesAtExactCapacity(t *testing.T) {
    ctx := context.Background()
    for _, tc := range []struct {
        name string
        records int
        size int
    }{
        {name: "record-count-4096", records: 4096, size: 128},
        {name: "byte-limit-16MiB", records: 2048, size: 8192},
    } {
        t.Run(tc.name, func(t *testing.T) {
            probe := newPrivateContinuousSinkProbe()
            probe.durable[3] = true
            router, err := newPrivateContinuousFamilyRouter(ctx, probe, 2)
            if err != nil { t.Fatal(err) }
            if err := router.BeginSourceWindow(ctx, 3); err != nil { t.Fatal(err) }
            for i := 1; i <= tc.records; i++ {
                row := privateContinuousFixture(3, 111, int64(i), "WindowsSecurityEvent", tc.size)
                if err := router.Add(ctx, row); err != nil { t.Fatal(err) }
                if i != tc.records && probe.flushes[privateFamilySecurity] != 0 {
                    t.Fatalf("premature capacity flush at record %d", i)
                }
            }
            if probe.flushes[privateFamilySecurity] != 1 ||
                len(probe.committed) != tc.records ||
                len(router.lanes[privateFamilySecurity].pending) != 0 ||
                router.outstanding[3] != 0 {
                t.Fatalf("exact limit was not committed: flushes=%v committed=%d pending=%d outstanding=%d",
                    probe.flushes, len(probe.committed),
                    len(router.lanes[privateFamilySecurity].pending), router.outstanding[3])
            }
            // The source window remains INPUT-open, so an early SQL capacity
            // commit must never publish its typed_window completion marker.
            if len(probe.projected) != 0 { t.Fatalf("marker published before close: %v", probe.projected) }
            if err := router.EndSourceWindow(ctx, 3); err != nil { t.Fatal(err) }
            if len(probe.projected) != 1 || probe.projected[0] != 3 {
                t.Fatalf("committed source not marked at input close: %v", probe.projected)
            }
            if err := router.EndOfInput(ctx); err != nil { t.Fatal(err) }
            if probe.flushes[privateFamilySecurity] != 1 {
                t.Fatalf("end-of-input caused duplicate capacity write: %v", probe.flushes)
            }
        })
    }
}

func TestPrivateContinuousExactCapacityFailureKeepsEntireBuffer(t *testing.T) {
    ctx := context.Background()
    probe := newPrivateContinuousSinkProbe()
    probe.durable[3] = true
    probe.failFamily = privateFamilySecurity
    router, err := newPrivateContinuousFamilyRouter(ctx, probe, 2)
    if err != nil { t.Fatal(err) }
    if err := router.BeginSourceWindow(ctx, 3); err != nil { t.Fatal(err) }
    for i := 1; i < 4096; i++ {
        if err := router.Add(ctx, privateContinuousFixture(3, 110, int64(i), "WindowsSecurityEvent", 128)); err != nil {
            t.Fatal(err)
        }
    }
    if err := router.Add(ctx, privateContinuousFixture(3, 110, 4096, "WindowsSecurityEvent", 128)); err == nil {
        t.Fatal("capacity SQL failure not propagated")
    }
    if len(router.lanes[privateFamilySecurity].pending) != 4096 ||
        router.outstanding[3] != 4096 ||
        len(probe.projected) != 0 ||
        len(probe.committed) != 0 {
        t.Fatal("failed exact-capacity SQL write lost records or published checkpoint")
    }
    // After a failed Add, the owning worker must stop and recover from
    // durable signed input; the queue still holds the complete failed batch.
}
