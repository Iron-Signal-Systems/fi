// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "bufio"
    "bytes"
    "context"
    "crypto/sha256"
    "errors"
    "fmt"
    "io"
    "strings"
    "sync"
    "sync/atomic"
    "testing"
    "time"
)

func TestPrivateParallelARejectsOtherModes(t *testing.T) {
    if _, err := WithPrivateParallelPreparationA(nil); err == nil {
        t.Fatal("nil context selected two-worker experiment")
    }
    if _, err := WithPrivateParallelPreparationA(context.Background()); err == nil {
        t.Fatal("ordinary FI path selected two-worker experiment")
    }
    if _, err := WithPrivateParallelPreparationA(privateMixedTestContext(t)); err == nil {
        t.Fatal("mixed only mode selected two-worker experiment")
    }
    ctx := privateDependencyTestContext(t)
    selected, err := WithPrivateParallelPreparationA(ctx)
    if err != nil {
        t.Fatalf("valid isolated combined-F3 context rejected at CLI selection: %v", err)
    }
    if !privateParallelARequested(selected) || privateParallelAEnabled(selected) {
        t.Fatal("initial F3 must select Candidate A but NOT activate workers before H16")
    }
    if err := privateParallelAActivationError(selected); err == nil {
        t.Fatal("requested F3 profile silently allowed sequential fallback")
    }
    // CLI applies WithPrivateFileHashH16 after the two-worker selector.
    // This precise F3 -> F3H16 conversion caused the signed benchmark to
    // run sequentially and fail only AFTER the database had finished.
    enabled, err := WithPrivateFileHashH16(selected)
    if err != nil {
        t.Fatalf("historical H16 conversion rejected: %v", err)
    }
    if got := fileBulkLimitsFromContext(enabled).Name; got != "F3H16" {
        t.Fatalf("runtime profile is not F3H16: %s", got)
    }
    if !privateParallelAEnabled(enabled) || privateParallelAActivationError(enabled) != nil {
        t.Fatal("exact F3H16 runtime did not activate two preparation workers")
    }
    mutated := context.WithValue(enabled, privateDependencyBuffersKey{}, false)
    if privateParallelAEnabled(mutated) || privateParallelAActivationError(mutated) == nil {
        t.Fatal("missing dependency isolation accepted instead of failing closed")
    }
    caps := fileBulkLimitsFromContext(enabled)
    caps.ObserveMaxBytes++
    modifiedCaps := context.WithValue(enabled, fileBulkProfileContextKey{}, caps)
    if privateParallelAEnabled(modifiedCaps) || privateParallelAActivationError(modifiedCaps) == nil {
        t.Fatal("altered H16 File limit silently fell back to sequential")
    }
    noField := context.WithValue(enabled, privateSecurityFieldPartitionsKey{}, false)
    if privateParallelAEnabled(noField) || privateParallelAActivationError(noField) == nil {
        t.Fatal("missing Security field isolation did not fail closed")
    }
    if privateParallelAEnabled(context.Background()) ||
        privateParallelAActivationError(context.Background()) != nil {
        t.Fatal("ordinary context activated or rejected normal FI path")
    }
}

func TestPrivateParallelAReordersExactSignedBytes(t *testing.T) {
    var original bytes.Buffer
    const count = 700
    for n := 1; n <= count; n++ {
        fmt.Fprintf(&original, "signed-record-%06d\n", n)
    }
    var active atomic.Int64
    var peak atomic.Int64
    fn := func(raw []byte) (SourceRecord, securityBulkRecord, bool, error) {
        curr := active.Add(1)
        defer active.Add(-1)
        for {
            prev := peak.Load()
            if curr <= prev || peak.CompareAndSwap(prev, curr) {
                break
            }
        }
        // Force the first record to finish AFTER its successor. The writer
        // must still see the original signed byte and ordinal sequence.
        if bytes.Equal(raw, []byte("signed-record-000001\n")) {
            time.Sleep(25 * time.Millisecond)
        }
        if bytes.Equal(raw, []byte("signed-record-000002\n")) {
            time.Sleep(4 * time.Millisecond)
        }
        return SourceRecord{RecordDigest: sha256.Sum256(raw)}, securityBulkRecord{}, false, nil
    }
    stream, err := newPrivateParallelPreparedStream(context.Background(), bufio.NewReader(bytes.NewReader(original.Bytes())), fn)
    if err != nil { t.Fatal(err) }
    defer stream.Close()
    expected := sha256.New()
    for n := 1; n <= count; n++ {
        line, ok := stream.Next()
        if !ok {
            t.Fatalf("early EOF at signed ordinal %d", n)
        }
        raw := []byte(fmt.Sprintf("signed-record-%06d\n", n))
        if line.ordinal != int64(n) || !bytes.Equal(line.raw, raw) {
            t.Fatalf("source order or bytes changed at %d (got ordinal %d)", n, line.ordinal)
        }
        if line.readErr != nil || line.prepareErr != nil {
            t.Fatalf("valid signed line %d failed: %v %v", n, line.readErr, line.prepareErr)
        }
        digest := sha256.Sum256(raw)
        if line.source.RecordDigest != digest {
            t.Fatalf("per-record digest differs at %d", n)
        }
        _, _ = expected.Write(line.raw)
    }
    if line, ok := stream.Next(); ok {
        t.Fatalf("unexpected record after EOF: ordinal=%d", line.ordinal)
    }
    got := expected.Sum(nil)
    want := sha256.Sum256(original.Bytes())
    if !bytes.Equal(got, want[:]) {
        t.Fatal("signed batch SHA changed by parallel preparation")
    }
    if peak.Load() < 2 {
        t.Fatalf("workers did not run concurrently; peak=%d", peak.Load())
    }
    if stream.rows != count {
        t.Fatalf("wrong prepared source rows %d", stream.rows)
    }
    if stream.peakReorder > privateParallelAMaxInFlight-1 {
        t.Fatalf("out-of-order buffer exceeded hard bound: %d", stream.peakReorder)
    }
}

func TestPrivateParallelAReadAheadIsStrictlyBounded(t *testing.T) {
    var records bytes.Buffer
    for i := 0; i < 500; i++ {
        fmt.Fprintf(&records, "row-%06d\n", i)
    }
    var prepCount atomic.Int64
    fn := func(raw []byte) (SourceRecord, securityBulkRecord, bool, error) {
        prepCount.Add(1)
        return SourceRecord{}, securityBulkRecord{}, false, nil
    }
    stream, err := newPrivateParallelPreparedStream(context.Background(), bufio.NewReader(&records), fn)
    if err != nil { t.Fatal(err) }
    defer stream.Close()
    time.Sleep(25*time.Millisecond)
    if got := prepCount.Load(); got > privateParallelAMaxInFlight {
        t.Fatalf("read ahead escaped %d-credit budget: %d", privateParallelAMaxInFlight, got)
    }
    for i := 0; i < 500; i++ {
        if _,ok := stream.Next(); !ok {t.Fatalf("early EOF at %d", i)}
    }
    if _,ok := stream.Next(); ok {t.Fatal("extra record")}
}

func TestPrivateParallelAFinalLFAndReadErrorPrecedence(t *testing.T) {
    var processed atomic.Int64
    fn := func(raw []byte) (SourceRecord, securityBulkRecord, bool, error) {
        processed.Add(1)
        return SourceRecord{}, securityBulkRecord{}, false, nil
    }
    stream, err := newPrivateParallelPreparedStream(context.Background(),
        bufio.NewReader(strings.NewReader("first\nlast-without-newline")), fn)
    if err != nil {t.Fatal(err)}
    first, ok := stream.Next()
    if !ok || first.readErr != nil || string(first.raw) != "first\n" {
        t.Fatal("first complete record changed")
    }
    last, ok := stream.Next()
    if !ok || last.ordinal != 2 || string(last.raw) != "last-without-newline" ||
        !errors.Is(last.readErr, io.EOF) {
        t.Fatalf("missing LF was silently normalized: %+v",last)
    }
    if got := processed.Load(); got != 1 {
        t.Fatalf("worker decoded malformed trailing line: count=%d",got)
    }
    stream.Close()
}

func TestPrivateParallelAFirstErrorPreservesSignedOrdinal(t *testing.T) {
    sentinel := errors.New("strict signed record rejection")
    fn := func(raw []byte) (SourceRecord, securityBulkRecord, bool, error) {
        if string(raw) == "first\n" { time.Sleep(20*time.Millisecond) }
        if string(raw) == "second\n" {
            return SourceRecord{}, securityBulkRecord{}, false, sentinel
        }
        return SourceRecord{}, securityBulkRecord{}, false, nil
    }
    stream, err := newPrivateParallelPreparedStream(context.Background(),
        bufio.NewReader(strings.NewReader("first\nsecond\nthird\n")), fn)
    if err != nil {t.Fatal(err)}
    defer stream.Close()
    first,_ := stream.Next()
    second,_ := stream.Next()
    third,_ := stream.Next()
    if first.ordinal != 1 || first.prepareErr != nil ||
        second.ordinal != 2 || !errors.Is(second.prepareErr,sentinel) ||
        third.ordinal != 3 || third.prepareErr != nil {
        t.Fatal("signed order/error precedence changed")
    }
}

func TestPrivateParallelAEarlyShutdownJoinsWorkers(t *testing.T) {
    ctx,cancel := context.WithCancel(context.Background())
    defer cancel()
    reader := strings.NewReader(strings.Repeat("long-valid-record\n",10000))
    fn := func(raw []byte) (SourceRecord,securityBulkRecord,bool,error) {
        return SourceRecord{},securityBulkRecord{},false,nil
    }
    stream,err := newPrivateParallelPreparedStream(ctx,bufio.NewReader(reader),fn)
    if err != nil {t.Fatal(err)}
    if _,ok := stream.Next();!ok {t.Fatal("failed first record")}
    finished := make(chan struct{})
    var once sync.Once
    go func() { once.Do(stream.Close); close(finished) }()
    select {
    case <-finished:
    case <-time.After(3*time.Second):
        t.Fatal("early database failure would leak preparation goroutines")
    }
    once.Do(stream.Close)
}

func TestPrivateParallelANilSourceRejected(t *testing.T) {
    fn := func(raw []byte) (SourceRecord, securityBulkRecord, bool,error){
        return SourceRecord{},securityBulkRecord{},false,nil
    }
    if _,err:=newPrivateParallelPreparedStream(context.Background(),nil,fn);err==nil {
        t.Fatal("nil source accepted")
    }
    if _,err:=newPrivateParallelPreparedStream(context.Background(),
        bufio.NewReader(strings.NewReader("x\n")),nil);err==nil {
        t.Fatal("nil preparer accepted")
    }
}
