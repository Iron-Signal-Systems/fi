// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package c1handoff

import (
    "bytes"
    "crypto/sha256"
    "errors"
    "io"
    "strings"
    "testing"
)

func sampleFrame() Frame {
    raw:=[]byte("{\"version\":\"fi-spool-record/0.1\",\"record_kind\":\"CollectorIdentity\"}\n")
    return Frame{
        Kind:Source,SourceID:"iss-fs-22a.iss.local",GenerationID:"generation-1",
        ReceiptSHA256:strings.Repeat("a",64),Sequence:1,
        Rows:[]Row{{SignedBatchIndex:0,SourceBatchID:10,Ordinal:1,RawRecord:raw,Digest:sha256.Sum256(raw)}},
    }
}
func TestC1HandoffFrameRoundTrip(t *testing.T){
    input:=sampleFrame()
    var bytesWritten bytes.Buffer
    if err:=WriteFrame(&bytesWritten,input);err!=nil{t.Fatal(err)}
    got,err:=ReadFrame(&bytesWritten);if err!=nil{t.Fatal(err)}
    if got.Sequence!=input.Sequence||got.Kind!=Source||len(got.Rows)!=1||
        got.Rows[0].Ordinal!=1||!bytes.Equal(got.Rows[0].RawRecord,input.Rows[0].RawRecord){
        t.Fatalf("signed C1 parent handoff altered: %+v",got)
    }
    var reply bytes.Buffer
    ack:=Frame{Kind:Ack,SourceID:input.SourceID,GenerationID:input.GenerationID,
        ReceiptSHA256:input.ReceiptSHA256,Sequence:input.Sequence,Committed:true}
    if err:=WriteFrame(&reply,ack);err!=nil{t.Fatal(err)}
    got,err=ReadFrame(&reply)
    if err!=nil||!got.Committed||got.Kind!=Ack{t.Fatalf("commit ACK lost: %+v %v",got,err)}
}
func TestC1HandoffRejectsForgedAndCorruptInput(t *testing.T){
    for name,mutate:=range map[string]func(*Frame){
        "bad-digest":func(f *Frame){f.Rows[0].Digest[0]^=1},
        "bad-ordinal":func(f *Frame){f.Rows[0].Ordinal=0},
        "bad-batch":func(f *Frame){f.Rows[0].SourceBatchID=0},
        "not-lf":func(f *Frame){f.Rows[0].RawRecord=[]byte("bad")},
        "bad-receipt":func(f *Frame){f.ReceiptSHA256="bad"},
        "fake-ack":func(f *Frame){f.Committed=true},
        "missing-sequence":func(f *Frame){f.Sequence=0},
        "extra-rows":func(f *Frame){f.Kind=Drain},
    }{
        t.Run(name,func(t *testing.T){
            f:=sampleFrame();mutate(&f)
            if err:=f.Validate();err==nil{t.Fatal("invalid source was accepted")}
        })
    }
    var encoded bytes.Buffer
    if err:=WriteFrame(&encoded,sampleFrame());err!=nil{t.Fatal(err)}
    valid:=encoded.Bytes()
    t.Run("tampered-wire",func(t *testing.T){
        altered:=append([]byte(nil),valid...);altered[len(altered)-1]^=1
        if _,err:=ReadFrame(bytes.NewReader(altered));err==nil{t.Fatal("accepted tampered transport")}
    })
    t.Run("oversized-header",func(t *testing.T){
        altered:=append([]byte(nil),valid...)
        for i:=8;i<12;i++ {altered[i]=255}
        if _,err:=ReadFrame(bytes.NewReader(altered));err==nil{t.Fatal("accepted oversized frame")}
    })
    t.Run("truncated-payload",func(t *testing.T){
        _,err:=ReadFrame(bytes.NewReader(valid[:len(valid)-1]))
        if !errors.Is(err,io.ErrUnexpectedEOF){t.Fatalf("expected truncated frame, got %v",err)}
    })
    t.Run("invalid-ack",func(t *testing.T){
        f:=sampleFrame();f.Kind=Ack;f.Rows=nil
        if err:=f.Validate();err==nil{t.Fatal("uncommitted acknowledgment accepted")}
    })
    t.Run("reordered-signed-batches",func(t *testing.T){
        f:=sampleFrame()
        f.Kind=Start
        f.Rows=nil
        f.BatchIDs=[]string{"batch-0002","batch-0001"}
        f.ExpectedRecords=2
        if err:=f.Validate();err==nil{
            t.Fatal("reordered signed batch manifest list accepted")
        }
    })
    t.Run("out-of-order",func(t *testing.T){
        f:=sampleFrame();f.Rows=append(f.Rows,f.Rows[0])
        if err:=f.Validate();err==nil{t.Fatal("duplicate signed row admitted")}
    })
}
