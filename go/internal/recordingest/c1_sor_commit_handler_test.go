//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "crypto/sha256"
    "errors"
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)

type c1SQLHandoffTestSink struct {
    parent,typed int
    sourceACK,familyACK bool
    failSource bool
}
func (s *c1SQLHandoffTestSink) Source(_ context.Context,rows []privateP6Record)error{
    s.parent+=len(rows);return nil
}
func (s *c1SQLHandoffTestSink) Family(_ context.Context,_ privateP6Family,rows []privateP6Record)error{
    s.typed+=len(rows);return nil
}
func (s *c1SQLHandoffTestSink) WaitSource(context.Context)error{
    if s.failSource{return errors.New("injected PostgreSQL COMMIT failure")}
    s.sourceACK=true;return nil
}
func (s *c1SQLHandoffTestSink) WaitFamily(context.Context,privateP6Family)error{
    s.familyACK=true;return nil
}
func (s *c1SQLHandoffTestSink) WaitAll(context.Context)error{return nil}

func c1SQLTestFrame(kind c1handoff.Kind,sequence uint64)c1handoff.Frame{
    raw:=[]byte("{\"version\":\"fi-spool-record/0.1\",\"record_kind\":\"CollectorIdentity\",\"scope_id\":\"scope-1\",\"written_at\":\"2026-11-21T13:00:00Z\",\"payload\":{\"name\":\"test\"}}\n")
    return c1handoff.Frame{
        Kind:kind,SourceID:"iss-fs-22a.iss.local",
        GenerationID:"generation-test",ReceiptSHA256:strings.Repeat("b",64),
        Sequence:sequence,Rows:[]c1handoff.Row{{SignedBatchIndex:0,
            SourceBatchID:55,Ordinal:1,RawRecord:raw,Digest:sha256.Sum256(raw)}},
    }
}
func TestC1SoRNativeProcessorRequiresCommitBeforeAcknowledgment(t *testing.T){
    sink:=&c1SQLHandoffTestSink{}
    h,err:=newC1SoRCommitHandler(sink,"iss-fs-22a.iss.local","generation-test",
        strings.Repeat("b",64),[]int64{55},1)
    if err!=nil{t.Fatal(err)}
    ctx:=context.Background()
    if err=h.Commit(ctx,c1SQLTestFrame(c1handoff.Source,1));err!=nil{t.Fatal(err)}
    if !sink.sourceACK||h.parentRows!=1{t.Fatal("SoR falsely acknowledged an uncommitted SourceParent row")}
    if err=h.Commit(ctx,c1SQLTestFrame(c1handoff.Other,2));err!=nil{t.Fatal(err)}
    if !sink.familyACK||h.typedRows!=1{t.Fatal("SoR falsely acknowledged uncommitted typed SQL")}
    drain:=c1SQLTestFrame(c1handoff.Drain,3);drain.Rows=nil
    if err=h.Commit(ctx,drain);err!=nil{t.Fatal(err)}
    if !h.drained {t.Fatal("final C1 source/typed gate not sealed")}
    if err=h.Commit(ctx,drain);err==nil{t.Fatal("second generation drain accepted")}
}
func TestC1SoRNativeProcessorFailsClosed(t *testing.T){
    for name,change:=range map[string]func(*c1handoff.Frame){
        "wrong-source-batch":func(f *c1handoff.Frame){f.Rows[0].SourceBatchID=56},
        "wrong-receipt":func(f *c1handoff.Frame){f.ReceiptSHA256=strings.Repeat("c",64)},
        "wrong-family":func(f *c1handoff.Frame){f.Kind=c1handoff.File},
        "unsigned-byte-change":func(f *c1handoff.Frame){f.Rows[0].RawRecord[0]='!'},
        "nonexistent-signed-batch":func(f *c1handoff.Frame){f.Rows[0].SignedBatchIndex=1},
    }{
        t.Run(name,func(t *testing.T){
            sink:=&c1SQLHandoffTestSink{}
            h,err:=newC1SoRCommitHandler(sink,"iss-fs-22a.iss.local","generation-test",
                strings.Repeat("b",64),[]int64{55},1);if err!=nil{t.Fatal(err)}
            f:=c1SQLTestFrame(c1handoff.Source,1);change(&f)
            if err=h.Commit(context.Background(),f);err==nil{t.Fatal("unauthorized cross-jail handoff accepted")}
            if sink.parent!=0{t.Fatal("invalid signed row reached PostgreSQL")}
        })
    }
    t.Run("SQL-COMMIT-error",func(t *testing.T){
        sink:=&c1SQLHandoffTestSink{failSource:true}
        h,err:=newC1SoRCommitHandler(sink,"iss-fs-22a.iss.local","generation-test",
            strings.Repeat("b",64),[]int64{55},1);if err!=nil{t.Fatal(err)}
        if err=h.Commit(context.Background(),c1SQLTestFrame(c1handoff.Source,1));err==nil{
            t.Fatal("SQL commit failure was incorrectly acknowledged")
        }
        if h.parentRows!=0{t.Fatal("failed PostgreSQL COMMIT counted durable")}
    })
    t.Run("no-parent",func(t *testing.T){
        sink:=&c1SQLHandoffTestSink{}
        h,err:=newC1SoRCommitHandler(sink,"iss-fs-22a.iss.local","generation-test",
            strings.Repeat("b",64),[]int64{55},1);if err!=nil{t.Fatal(err)}
        if err=h.Commit(context.Background(),c1SQLTestFrame(c1handoff.Other,1));err==nil{
            t.Fatal("typed SQL accepted before parent handoff")
        }
    })
    t.Run("seed-prefix-not-replayed",func(t *testing.T){
        sink:=&c1SQLHandoffTestSink{}
        h,err:=newC1SoRCommitHandler(sink,"iss-fs-22a.iss.local","generation-test",
            strings.Repeat("b",64),[]int64{55,56},1)
        if err!=nil{t.Fatal(err)}
        h.minBatchIndex=1
        old:=c1SQLTestFrame(c1handoff.Source,2)
        if err=h.Commit(context.Background(),old);err==nil{
            t.Fatal("a signed row from immutable verified seed was re-admitted")
        }
        if sink.parent!=0{t.Fatal("seed prefix replay reached PostgreSQL")}
    })
    t.Run("premature-drain",func(t *testing.T){
        sink:=&c1SQLHandoffTestSink{}
        h,err:=newC1SoRCommitHandler(sink,"iss-fs-22a.iss.local","generation-test",
            strings.Repeat("b",64),[]int64{55},1);if err!=nil{t.Fatal(err)}
        d:=c1SQLTestFrame(c1handoff.Drain,1);d.Rows=nil
        if err=h.Commit(context.Background(),d);err==nil{
            t.Fatal("C1 prematurely accepted partially committed generation")
        }
    })
}
