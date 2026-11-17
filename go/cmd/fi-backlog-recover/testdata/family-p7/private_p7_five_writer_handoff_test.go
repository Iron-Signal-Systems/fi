// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// P7 private development: prove TRUE independent workers, bounded in-flight
// memory, exactly-once signed source membership and File->USN dependency.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "sync"
    "testing"
    "time"
)

type privateP7TestLedger struct{
    mu sync.Mutex
    records []privateP6Record
    closed bool
    fail bool
}
func(l *privateP7TestLedger)Source(_ context.Context,r []privateP6Record)error{
    l.mu.Lock();defer l.mu.Unlock()
    if l.fail{return errors.New("injected source parent COPY error")}
    l.records=append(l.records,r...)
    return nil
}
func(l *privateP7TestLedger)Close(context.Context)error{
    l.mu.Lock();l.closed=true;l.mu.Unlock();return nil
}
type privateP7TestWriter struct{
    family privateP6Family
    started chan privateP6Family
    release <-chan struct{}
    failed bool
    mu sync.Mutex
    calls int
    rows int64
    closed bool
}
func(w *privateP7TestWriter)Write(ctx context.Context,rows []privateP6Record)error{
    if w.started!=nil{
        select{
        case w.started<-w.family:
        case <-ctx.Done():return ctx.Err()
        }
    }
    if w.release!=nil{
        select{
        case <-w.release:
        case <-ctx.Done():return ctx.Err()
        }
    }
    if w.failed{return errors.New("injected typed relational/FK SQL failure")}
    w.mu.Lock();w.calls++;w.rows+=int64(len(rows));w.mu.Unlock()
    return nil
}
func(w *privateP7TestWriter)Close(context.Context)error{
    w.mu.Lock();w.closed=true;w.mu.Unlock();return nil
}

func privateP7TestEngine(t *testing.T,ledger *privateP7TestLedger,
    started chan privateP6Family,release <-chan struct{},
    fail privateP6Family,
)(*privateP7FiveWriter,[privateP6FamilyCount]*privateP7TestWriter){
    t.Helper()
    var writers [privateP6FamilyCount]*privateP7TestWriter
    factory:=func(_ context.Context,f privateP6Family)(
        privateP7FamilyWriter,error,
    ){
        w:=&privateP7TestWriter{
            family:f,started:started,release:release,
            failed:fail==f,
        }
        writers[f]=w
        return w,nil
    }
    engine,err:=newPrivateP7FiveWriter(context.Background(),ledger,factory)
    if err!=nil{t.Fatal(err)}
    return engine,writers
}
func privateP7Rows()[]privateP6Record{
    return []privateP6Record{
        privateP6Fixture(1,1,"WindowsSecurityEvent"),
        privateP6Fixture(1,2,"FileObservation"),
        privateP6Fixture(1,3,"WindowsSecurityCoverage"),
        privateP6Fixture(1,4,"USNReadBoundary"),
        privateP6Fixture(1,5,"CollectorIdentity"),
    }
}

func TestPrivateP7FiveSeparateFamilyWritersWithUSNFileFence(t *testing.T){
    ledger:=&privateP7TestLedger{}
    started:=make(chan privateP6Family,10)
    release:=make(chan struct{})
    sink,writers:=privateP7TestEngine(t,ledger,started,release,privateP6FamilyCount)
    defer sink.Close(context.Background())
    rows:=privateP7Rows()
    if err:=sink.Source(context.Background(),rows);err!=nil{t.Fatal(err)}
    // Three independent writers and File must all begin concurrently.
    for _,f:=range []privateP6Family{privateP6Security,privateP6File,
        privateP6Coverage,privateP6Other}{
        if err:=sink.Family(context.Background(),f,rows[f:f+1]);err!=nil{t.Fatal(err)}
    }
    first:=make(map[privateP6Family]bool)
    for len(first)<4{
        select{
        case f:=<-started:first[f]=true
        case <-time.After(3*time.Second):t.Fatalf("only %d of 4 independent SQL writers started",len(first))
        }
    }
    for _,f:=range []privateP6Family{privateP6Security,privateP6File,
        privateP6Coverage,privateP6Other}{
        if !first[f]{t.Fatalf("family %s was not started",privateP6FamilyNames[f])}
    }
    usnSent:=make(chan error,1)
    go func(){usnSent<-sink.Family(context.Background(),privateP6USN,rows[3:4])}()
    select{
    case err:=<-usnSent:t.Fatalf("USN crossed uncommitted File dependency: %v",err)
    case <-time.After(25*time.Millisecond):
    }
    close(release)
    select{
    case err:=<-usnSent:if err!=nil{t.Fatal(err)}
    case <-time.After(3*time.Second):t.Fatal("USN stuck after File committed")
    }
    if err:=sink.Drain(context.Background());err!=nil{t.Fatal(err)}
    s,n,peak,family:=sink.Stats()
    if s!=5||n!=5||peak<1||family[privateP6File]!=1||
        family[privateP6USN]!=1{
        t.Fatalf("five family committed records mismatched source=%d typed=%d bytes=%d by=%v",s,n,peak,family)
    }
    for f,w:=range writers{
        w.mu.Lock()
        done:=w.rows
        w.mu.Unlock()
        if done!=1{t.Fatalf("family=%s committed=%d want=1",privateP6FamilyNames[f],done)}
    }
}

func TestPrivateP7SignedParentRequiredAndExactlyOnce(t *testing.T){
    ledger:=&privateP7TestLedger{}
    sink,_:=privateP7TestEngine(t,ledger,nil,nil,privateP6FamilyCount)
    defer sink.Close(context.Background())
    r:=privateP6Fixture(1,1,"FileObservation")
    if err:=sink.Family(context.Background(),privateP6File,[]privateP6Record{r});err==nil{
        t.Fatal("uncommitted source parent was accepted by SQL writer")
    }
    if err:=sink.Source(context.Background(),[]privateP6Record{r});err!=nil{t.Fatal(err)}
    if err:=sink.Source(context.Background(),[]privateP6Record{r});err==nil{
        t.Fatal("same signed parent was committed twice")
    }
    wrong:=r
    wrong.prepared.RecordDigest[0]=0xbb
    if err:=sink.Family(context.Background(),privateP6File,[]privateP6Record{wrong});err==nil{
        t.Fatal("changed SHA-256 was accepted as original signed source")
    }
    if err:=sink.Family(context.Background(),privateP6File,[]privateP6Record{r});err!=nil{t.Fatal(err)}
    if err:=sink.Family(context.Background(),privateP6File,[]privateP6Record{r});err==nil{
        t.Fatal("same signed child was queued twice")
    }
    if err:=sink.Drain(context.Background());err!=nil{t.Fatal(err)}
}

func TestPrivateP7CannotPublishWithMissingChild(t *testing.T){
    ledger:=&privateP7TestLedger{}
    sink,_:=privateP7TestEngine(t,ledger,nil,nil,privateP6FamilyCount)
    defer sink.Close(context.Background())
    rows:=privateP7Rows()
    if err:=sink.Source(context.Background(),rows);err!=nil{t.Fatal(err)}
    for i,r:=range rows[:len(rows)-1]{
        f,_:=privateP6KindFamily(r.prepared.Record.RecordKind)
        if err:=sink.Family(context.Background(),f,rows[i:i+1]);err!=nil{t.Fatal(err)}
    }
    if err:=sink.Drain(context.Background());err==nil{
        t.Fatal("incomplete signed typed source would allow W512 publication")
    }
    if sink.drained{t.Fatal("failed final barrier falsely counted as published")}
}

func TestPrivateP7SQLWriterErrorFailsEntireWindow(t *testing.T){
    ledger:=&privateP7TestLedger{}
    sink,_:=privateP7TestEngine(t,ledger,nil,nil,privateP6Coverage)
    defer sink.Close(context.Background())
    row:=privateP6Fixture(1,1,"WindowsSecurityCoverage")
    if err:=sink.Source(context.Background(),[]privateP6Record{row});err!=nil{t.Fatal(err)}
    if err:=sink.Family(context.Background(),privateP6Coverage,[]privateP6Record{row});err!=nil{t.Fatal(err)}
    ctx,cancel:=context.WithTimeout(context.Background(),2*time.Second)
    defer cancel()
    if err:=sink.Drain(ctx);err==nil{
        t.Fatal("failed typed SQL child COPY was ignored")
    }
    if sink.drained{t.Fatal("failed SQL transaction allowed completed marker")}
}

func TestPrivateP7ParentCopyErrorAbortsWithoutTypedRows(t *testing.T){
    ledger:=&privateP7TestLedger{fail:true}
    sink,_:=privateP7TestEngine(t,ledger,nil,nil,privateP6FamilyCount)
    defer sink.Close(context.Background())
    row:=privateP6Fixture(1,1,"WindowsSecurityEvent")
    if err:=sink.Source(context.Background(),[]privateP6Record{row});err==nil{
        t.Fatal("failed signed source COPY allowed dependent child")
    }
    if _,committed,_,_:=sink.Stats();committed!=0 {
        t.Fatalf("typed SQL committed %d after source parent failure",committed)
    }
}

func TestPrivateP7WeightedBoundAndCancellation(t *testing.T){
    ledger:=&privateP7TestLedger{}
    sink,_:=privateP7TestEngine(t,ledger,nil,nil,privateP6FamilyCount)
    defer sink.Close(context.Background())
    ctx:=context.Background()
    if err:=sink.reserve(ctx,privateP7MaxQueuedBytes+1);err==nil{
        t.Fatal("unbounded SQL work over 256MiB accepted")
    }
    if err:=sink.reserve(ctx,privateP7MaxQueuedBytes-1);err!=nil{t.Fatal(err)}
    blockedCtx,cancel:=context.WithTimeout(ctx,35*time.Millisecond)
    defer cancel()
    if err:=sink.reserve(blockedCtx,2);err==nil{
        t.Fatal("queued SQL memory budget did not exert backpressure")
    }
    sink.release(privateP7MaxQueuedBytes-1)
    if err:=sink.reserve(ctx,2);err!=nil{t.Fatal(err)}
    sink.release(2)
    if _,_,peak,_:=sink.Stats();peak!=privateP7MaxQueuedBytes-1{
        t.Fatalf("peak SQL admission bytes=%d",peak)
    }
}

func TestPrivateP7OpeningOneOfFiveConnectionsFailsClosed(t *testing.T){
    ledger:=&privateP7TestLedger{}
    opened:=0
    factory:=func(_ context.Context,f privateP6Family)(privateP7FamilyWriter,error){
        opened++
        if f==privateP6USN{return nil,errors.New("injected fifth PostgreSQL connection failure")}
        return &privateP7TestWriter{family:f},nil
    }
    if engine,err:=newPrivateP7FiveWriter(context.Background(),ledger,factory);
       err==nil||engine!=nil{
        t.Fatal("partial PostgreSQL writer allocation did not fail closed")
    }
    ledger.mu.Lock();closed:=ledger.closed;ledger.mu.Unlock()
    if !closed||opened!=4{
        t.Fatal(fmt.Sprintf("partially opened five SQL writers not cleaned up opened=%d ledgerClosed=%v",opened,closed))
    }
}

func TestPrivateP7DeferredVerifiedCacheCreatesPhysicalSignedWindow(t *testing.T){
    // Reproduce P7's C220 2026-11-17 failure: the durable signed
    // artifact checkpoint already exists, but deferred materialization
    // leaves the window-00000001 directory absent. The P7 source
    // ledger MUST create+verify actual 0600 signed files before SQL.
    g:=privateBacklogStageFixture(t)
    root:=privateBacklogTestRoot(t)
    limits:=BacklogWindowLimits{MaxRecords:6,MaxDataBytes:32}
    descriptors,err:=DescribeBacklogWindows(g,limits)
    if err!=nil||len(descriptors)!=2{
        t.Fatalf("FI P7 signed fixture W512 window count %d: %v",len(descriptors),err)
    }
    d:=descriptors[1]
    expected:=filepath.Join(root,"receipt-"+d.ReceiptSHA256,"window-00000001")
    if _,err:=os.Lstat(expected);!os.IsNotExist(err){
        t.Fatal("FI P7: test needs truly deferred window without a physical directory")
    }
    path,err:=privateP7MaterializeSignedWindow(
        context.Background(),g,limits,1,root,d)
    if err!=nil||path!=expected{
        t.Fatalf("FI P7: private physical source stage %q want %q: %v",
            path,expected,err)
    }
    if err:=VerifyMaterializedBacklogWindow(
        context.Background(),g,limits,1,root);err!=nil{
        t.Fatalf("FI P7: staged signed source bytes failed re-verification: %v",err)
    }
    pathAgain,err:=privateP7MaterializeSignedWindow(
        context.Background(),g,limits,1,root,d)
    if err!=nil||pathAgain!=path{
        t.Fatalf("FI P7: existing complete stage not safely reused %q: %v",pathAgain,err)
    }
    bad:=filepath.Join(path,"batch-00000002.data")
    original,err:=os.ReadFile(g.Batches[2].DataPath)
    if err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(bad,[]byte("corrupt!"),0600);err!=nil{t.Fatal(err)}
    if _,err:=privateP7MaterializeSignedWindow(
        context.Background(),g,limits,1,root,d);err==nil{
        t.Fatal("FI P7: tampered private source copy was accepted and published")
    }
    current,err:=os.ReadFile(g.Batches[2].DataPath)
    if err!=nil||string(current)!=string(original){
        t.Fatalf("FI P7: independent signed source cache was modified: %v",err)
    }
    mutated:=d
    mutated.DigestSHA256="mutated"
    if _,err:=privateP7MaterializeSignedWindow(
        context.Background(),g,limits,1,root,mutated);err==nil{
        t.Fatal("FI P7: changed signed window descriptor was accepted")
    }
}

func TestPrivateP7OwnedSignedWindowUsesCanonicalSHAInsteadOfForeignDeferredClone(t *testing.T){
    // Regression for the actual C220 failure after the first physical
    // source + artifact + source checkpoints committed: the outer
    // deferredWindow context refers to a DIFFERENT owned COW path.
    // P7 signs and hashes its own materialized source directory, so
    // reusing that unrelated SHA-once evidence must be prohibited.
    g:=privateBacklogStageFixture(t)
    root:=privateBacklogTestRoot(t)
    limits:=BacklogWindowLimits{MaxRecords:6,MaxDataBytes:32}
    descriptors,err:=DescribeBacklogWindows(g,limits)
    if err!=nil||len(descriptors)!=2{t.Fatalf("FI P7 fixture: %v",err)}
    d:=descriptors[1]
    stage,err:=privateP7MaterializeSignedWindow(
        context.Background(),g,limits,1,root,d)
    if err!=nil{t.Fatal(err)}
    i:=d.StartBatch
    batch:=g.Batches[i]
    batch.DataPath=filepath.Join(stage,fmt.Sprintf("batch-%08d.data",i))
    file,err:=os.Open(batch.DataPath)
    if err!=nil{t.Fatal(err)}
    defer file.Close()

    // Simulate the existing accelerated deferred-clone context held by
    // the outer C220 runner. The original SHA-once helper MUST reject
    // the independently staged signed source path.
    wrongDeferred:=&deferredBacklogWindow{
        pending:filepath.Join(root,"a-different-owned-clone"),
    }
    outer:=context.WithValue(context.Background(),privateDeferredWindowKey{},wrongDeferred)
    if proof,err:=privateReuseSignedBatchDigest(outer,batch,file);err==nil||proof!=nil{
        t.Fatal("FI P7 fixture did not reproduce foreign owned-clone failure")
    }
    canonical:=privateP7CanonicalSignedBatchContext(outer,i)
    if deferredWindowFromContext(canonical)!=nil{
        t.Fatal("FI P7 canonical reader retained foreign deferred SHA-once entitlement")
    }
    if deferredWindowFromContext(outer)!=wrongDeferred{
        t.Fatal("FI P7 changed the enclosing deferred clone ownership context")
    }
    if index,ok:=canonical.Value(privateP7SignedBatchIndexKey{}).(int);!ok||index!=i{
        t.Fatal("FI P7 canonical reader lost original authenticated batch index")
    }
    proof,err:=privateReuseSignedBatchDigest(canonical,batch,file)
    if err!=nil||proof!=nil{
        t.Fatalf("FI P7 independent signed source did not select original per-batch SHA path: proof=%v err=%v",proof,err)
    }
    // The canonical reader hashes actual LF-terminated source bytes;
    // this test verifies that the path it opens is the exact original
    // signed physical materialization, not the foreign COW clone.
    if err:=VerifyMaterializedBacklogWindow(context.Background(),g,limits,1,root);err!=nil{
        t.Fatalf("FI P7 independently staged signed source failed full SHA verification: %v",err)
    }
}

func TestPrivateP7CanonicalSignedReaderDoesNotRequireLegacyK32Chunk(t *testing.T) {
    // Actual C220 failure: the outer private W512 context still enables
    // W128 mixed-family routing, but P7 has its own five-family P6 buffer
    // session and never creates a legacy backlogTypedChunkDirective.
    owner:=&privateP6Buffers{}
    outer:=context.WithValue(context.Background(),privateMixedFamilyBuffersKey{},true)
    outer=context.WithValue(outer,privateDependencyBuffersKey{},true)
    outer=context.WithValue(outer,privateP6WindowContextKey{},owner)
    outer=context.WithValue(outer,backlogTypedChunkContextKey{},backlogTypedChunkDirective{})
    if err:=validatePrivateFamilyRoute(outer);err==nil {
        t.Fatal("FI P7 fixture did not reproduce legacy K32 rejection")
    }

    signed:=privateP7CanonicalSignedBatchContext(outer,205)
    if err:=validatePrivateFamilyRoute(signed);err!=nil {
        t.Fatalf("FI P7 canonical signed reader inherited obsolete K32 route: %v",err)
    }
    if privateMixedFamilyBuffersEnabled(signed)||privateDependencyBuffersEnabled(signed) {
        t.Fatal("FI P7 reader incorrectly kept legacy mixed/dependency route")
    }
    if _,ok:=signed.Value(backlogTypedChunkContextKey{}).(backlogTypedChunkDirective);ok {
        t.Fatal("FI P7 reader retained legacy typed chunk state")
    }
    if privateP6BuffersFromContext(signed)!=owner {
        t.Fatal("FI P7 reader lost its actual bounded five-family SQL session")
    }
    if i,ok:=signed.Value(privateP7SignedBatchIndexKey{}).(int);!ok||i!=205 {
        t.Fatal("FI P7 canonical signed batch identity lost")
    }
    if !privateMixedFamilyBuffersEnabled(outer)||
        outer.Value(privateDependencyBuffersKey{})!=true||
        privateP6BuffersFromContext(outer)!=owner {
        t.Fatal("FI P7 mutated the enclosing private benchmark context")
    }
}
