//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "errors"
    "os"
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)

func c1RAMTestStore(t *testing.T)*c1handoff.RAMStore{
    t.Helper()
    dir:=t.TempDir()
    if e:=os.Chmod(dir,0700);e!=nil{t.Fatal(e)}
    store,e:=c1handoff.NewRAMStore(dir)
    if e!=nil{t.Fatal(e)}
    return store
}
func c1RAMTestFrame(t *testing.T,store *c1handoff.RAMStore,
    kind c1handoff.Kind,seq uint64)c1handoff.Frame{
    t.Helper()
    frame:=c1SQLTestFrame(kind,seq)
    prepared,e:=PrepareSourceRecord(frame.Rows[0].RawRecord)
    if e!=nil{t.Fatal(e)}
    rows:=[]privateP6Record{{signedBatchIndex:0,
        sourceBatchID:55,ordinal:1,prepared:prepared}}
    data,e:=encodeC1PreparedRAMRows(rows)
    if e!=nil{t.Fatal(e)}
    ref,e:=store.Put(data,1)
    if e!=nil{t.Fatal(e)}
    frame.Rows=nil
    frame.Shared=ref
    return frame
}

func TestC1SharedRAMTwoJailSQLPathPreservesOriginalSource(t *testing.T){
    store:=c1RAMTestStore(t)
    sink:=&c1SQLHandoffTestSink{}
    h,e:=newC1SoRCommitHandler(sink,"iss-fs-22a.iss.local",
        "generation-test",strings.Repeat("b",64),[]int64{55},[]int64{1},1)
    if e!=nil{t.Fatal(e)}
    h.sharedRAM=store
    ctx:=context.Background()
    parent:=c1RAMTestFrame(t,store,c1handoff.Source,1)
    if e=h.Commit(ctx,parent);e!=nil{t.Fatal(e)}
    if sink.parent!=1||!sink.sourceACK{t.Fatal("shared RAM did not commit ordered SourceParent")}
    typed:=c1RAMTestFrame(t,store,c1handoff.Other,2)
    if e=h.Commit(ctx,typed);e!=nil{t.Fatal(e)}
    if sink.typed!=1||!sink.familyACK{t.Fatal("shared RAM did not commit original typed family")}
    drain:=c1SQLTestFrame(c1handoff.Drain,3);drain.Rows=nil
    if e=h.Commit(ctx,drain);e!=nil{t.Fatal(e)}
    if !h.drained{t.Fatal("RAM transport did not complete signed private SQL drain")}
}
func TestC1SharedRAMTamperRejectsBeforeSQL(t *testing.T){
    store:=c1RAMTestStore(t)
    sink:=&c1SQLHandoffTestSink{}
    h,e:=newC1SoRCommitHandler(sink,"iss-fs-22a.iss.local",
        "generation-test",strings.Repeat("b",64),[]int64{55},[]int64{1},1)
    if e!=nil{t.Fatal(e)}
    h.sharedRAM=store
    frame:=c1RAMTestFrame(t,store,c1handoff.Source,1)
    frame.Shared.SHA256[0]^=1
    if e=h.Commit(context.Background(),frame);e==nil{
        t.Fatal("tampered shared object admitted into fi-sor SQL")
    }
    if sink.parent!=0{t.Fatal("tamper reached SQL sink")}
}
type c1RAMFakeCommitSender struct {
    received []c1handoff.Frame
    future chan error
}
func(s *c1RAMFakeCommitSender)Send(ctx context.Context,f c1handoff.Frame)error{
    return errors.New("test requires asynchronous COMMIT future")
}
func(s *c1RAMFakeCommitSender)Submit(ctx context.Context,f c1handoff.Frame)(<-chan error,error){
    s.received=append(s.received,f)
    return s.future,nil
}
func(s *c1RAMFakeCommitSender)WaitAll(context.Context)error{return nil}

func TestC1SharedRAMProducerReclaimsOnlyAfterCommitACK(t *testing.T){
    store:=c1RAMTestStore(t)
    sender:=&c1RAMFakeCommitSender{future:make(chan error,1)}
    sink,e:=newC1RemoteSoRSink(sender,"iss-fs-22a.iss.local",
        "generation-test",strings.Repeat("b",64))
    if e!=nil{t.Fatal(e)}
    sink.next=2
    if e=sink.EnableSharedRAM(store);e!=nil{t.Fatal(e)}
    prepared,e:=PrepareSourceRecord(c1SQLTestFrame(c1handoff.Source,1).Rows[0].RawRecord)
    if e!=nil{t.Fatal(e)}
    if e=sink.Source(context.Background(),[]privateP6Record{{
        sourceBatchID:55,signedBatchIndex:0,ordinal:1,prepared:prepared,
    }});e!=nil{t.Fatal(e)}
    if len(sender.received)!=1||sender.received[0].Shared.Name==""||
        len(sender.received[0].Rows)!=0{
        t.Fatal("fi-ingest failed to publish prepared-only shared RAM reference")
    }
    ref:=sender.received[0].Shared
    if _,e=store.Get(ref);e!=nil{t.Fatal(e)}
    // No SQL completion yet: producer MUST NOT free the in-flight buffer.
    if _,e=store.Get(ref);e!=nil{t.Fatal("buffer reclaimed before commit ACK")}
    sender.future<-nil
    close(sender.future)
    if e=sink.WaitAll(context.Background());e!=nil{t.Fatal(e)}
    if _,e=store.Get(ref);!os.IsNotExist(e){t.Fatalf("buffer not reclaimed after exact COMMIT ACK: %v",e)}
}
