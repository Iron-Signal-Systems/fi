// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package c1handoff

import (
    "bytes"
    "context"
    "crypto/tls"
    "errors"
    "net"
    "strings"
    "testing"
    "time"
)

func TestC1FinalProofOnlyOnCommittedAck(t *testing.T){
    f:=sampleFrame()
    for name,mutate:=range map[string]func(*Frame){
        "source-forged-B":func(x *Frame){x.FinalStatus=FinalVerified},
        "source-forged-Accepted":func(x *Frame){x.FinalStatus=FinalAccepted},
        "invalid-enumeration":func(x *Frame){
            x.Kind=Ack;x.Rows=nil;x.Committed=true;x.FinalStatus=FinalStatus(255)
        },
        "rejected-ack-forges-B":func(x *Frame){
            x.Kind=Ack;x.Rows=nil;x.Error="denied";x.FinalStatus=FinalVerified
        },
        "START-id-map-forges-B":func(x *Frame){
            x.Kind=Ack;x.Rows=nil;x.Committed=true
            x.BatchSQLIDs=[]int64{9};x.FinalStatus=FinalVerified
        },
        "unverified-control":func(x *Frame){
            x.Kind=Drain;x.Rows=nil;x.FinalStatus=FinalVerified
        },
    }{
        t.Run(name,func(t *testing.T){
            a:=f;mutate(&a)
            if err:=a.Validate();err==nil{t.Fatal("accepted forged/invalid final proof")}
        })
    }
    for _,status:=range []FinalStatus{FinalNone,FinalVerified,FinalAccepted}{
        ack:=Frame{Kind:Ack,SourceID:f.SourceID,GenerationID:f.GenerationID,
            ReceiptSHA256:f.ReceiptSHA256,Sequence:13,Committed:true,
            FinalStatus:status}
        var wire bytes.Buffer
        if err:=WriteFrame(&wire,ack);err!=nil{t.Fatal(err)}
        decoded,err:=ReadFrame(&wire)
        if err!=nil||decoded.FinalStatus!=status{
            t.Fatalf("independent/canonical result changed status=%d decoded=%+v: %v",status,decoded,err)
        }
    }
}
func TestC1FinalProofV2RejectsOldProtocol(t *testing.T){
    sample:=sampleFrame()
    var wire bytes.Buffer
    if err:=WriteFrame(&wire,sample);err!=nil{t.Fatal(err)}
    old:=append([]byte(nil),wire.Bytes()...)
    copy(old[:8],[]byte("FIC1HND1"))
    if _,err:=ReadFrame(bytes.NewReader(old));err==nil{
        t.Fatal("old mixed-version SQL protocol was accepted")
    }
}
func TestC1AuthenticatedFinalProofDistinctFromSQLAck(t *testing.T){
    for _,tc:=range []struct{
        name string
        proof FinalStatus
        fail bool
    }{
        {"SQL-only-must-fail",FinalNone,true},
        {"independent-B-not-canonical",FinalVerified,false},
        {"canonical-Accepted-only-after-B",FinalAccepted,false},
    }{
        t.Run(tc.name,func(t *testing.T){
            serverFiles,clientFiles:=issueTestIdentity(t)
            serverTLS,e:=ServerTLSConfig(serverFiles,"fi-ingest.local");if e!=nil{t.Fatal(e)}
            clientTLS,e:=ClientTLSConfig(clientFiles,"fi-sor.local");if e!=nil{t.Fatal(e)}
            a,b:=net.Pipe()
            defer a.Close();defer b.Close()
            srverr:=make(chan error,1)
            server:=&Server{
                IOTimeout:5*time.Second,
                Bootstrap:func(_ context.Context,f Frame)([]int64,error){
                    if f.Kind!=Start||len(f.BatchIDs)!=1||f.BatchIDs[0]!="original"{
                        return nil,errors.New("untrusted source")
                    }
                    return []int64{1},nil
                },
                Dispatch:func(_ context.Context,f Frame)(<-chan error,error){
                    if f.Kind!=Source{return nil,errors.New("wrong SQL phase")}
                    done:=make(chan error,1);done<-nil;close(done)
                    return done,nil
                },
                Handler:func(_ context.Context,f Frame)error{
                    if f.Kind!=Drain{return errors.New("wrong final phase")}
                    return nil
                },
                FinalProof:func(_ context.Context,f Frame)(FinalStatus,error){
                    if f.Kind!=Drain{return FinalNone,errors.New("not Drain")}
                    return tc.proof,nil
                },
            }
            go func(){srverr<-server.ServeConn(context.Background(),tls.Server(a,serverTLS))}()
            client,e:=NewClient(tls.Client(b,clientTLS));if e!=nil{t.Fatal(e)}
            defer client.Close()
            raw:=sampleFrame()
            start:=Frame{Kind:Start,SourceID:raw.SourceID,
                GenerationID:raw.GenerationID,ReceiptSHA256:raw.ReceiptSHA256,
                Sequence:1,BatchIDs:[]string{"original"},ExpectedRecords:1}
            ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
            defer cancel()
            if e=client.Send(ctx,start);e!=nil{t.Fatal(e)}
            pipeline,e:=NewClientPipeline(ctx,client,4);if e!=nil{t.Fatal(e)}
            defer pipeline.Close()
            raw.Sequence=2
            if e=pipeline.Send(ctx,raw);e!=nil{t.Fatal(e)}
            if _,e=pipeline.FinalProof();e==nil{
                t.Fatal("SQL source ACK supplied an independent final proof")
            }
            drain:=Frame{Kind:Drain,SourceID:raw.SourceID,
                GenerationID:raw.GenerationID,ReceiptSHA256:raw.ReceiptSHA256,
                Sequence:3}
            if e=pipeline.Send(ctx,drain);e!=nil{t.Fatal(e)}
            proof,e:=pipeline.FinalProof()
            if tc.fail{
                if e==nil||!strings.Contains(e.Error(),"independent B"){
                    t.Fatalf("accepted SQL-only final Drain: %v %v",proof,e)
                }
            }else if e!=nil||proof!=tc.proof{
                t.Fatalf("final authenticated proof incorrect got=%d err=%v want=%d",proof,e,tc.proof)
            }
            if e=<-srverr;e!=nil{t.Fatal(e)}
        })
    }
}
