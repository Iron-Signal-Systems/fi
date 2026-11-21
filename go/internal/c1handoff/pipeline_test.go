// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package c1handoff

import (
    "context"
    "crypto/tls"
    "errors"
    "net"
    "strings"
    "testing"
    "time"
)

func TestC1PipelineKeepsTwoSQLCommitFuturesInFlight(t *testing.T){
    serverFiles,clientFiles:=issueTestIdentity(t)
    serverTLS,err:=ServerTLSConfig(serverFiles,"fi-ingest.local")
    if err!=nil{t.Fatal(err)}
    clientTLS,err:=ClientTLSConfig(clientFiles,"fi-sor.local")
    if err!=nil{t.Fatal(err)}
    rawServer,rawClient:=net.Pipe()
    defer rawServer.Close();defer rawClient.Close()
    releaseFirst:=make(chan struct{})
    releaseSecond:=make(chan struct{})
    observed:=make(chan uint64,2)
    serverDone:=make(chan error,1)
    srv:=&Server{
        IOTimeout:5*time.Second,
        Bootstrap:func(_ context.Context,f Frame)([]int64,error){
            if f.Kind!=Start||len(f.BatchIDs)!=1||f.BatchIDs[0]!="batch-1"{
                return nil,errors.New("wrong signed source Start")
            }
            return []int64{55},nil
        },
        Handler:func(_ context.Context,f Frame)error{
            if f.Kind!=Drain && f.Kind!=Seal{return errors.New("unexpected synchronous SQL")}
            return nil
        },
        Dispatch:func(ctx context.Context,f Frame)(<-chan error,error){
            if f.Kind!=Source{return nil,errors.New("unexpected native C1 family")}
            result:=make(chan error,1)
            observed<-f.Sequence
            go func(){
                if f.Sequence==2 {
                    select{case <-releaseFirst:case <-ctx.Done():result<-ctx.Err();close(result);return}
                }else{
                    select{case <-releaseSecond:case <-ctx.Done():result<-ctx.Err();close(result);return}
                }
                result<-nil
                close(result)
            }()
            return result,nil
        },
    }
    go func(){serverDone<-srv.ServeConn(context.Background(),tls.Server(rawServer,serverTLS))}()
    client,err:=NewClient(tls.Client(rawClient,clientTLS))
    if err!=nil{t.Fatal(err)}
    defer client.Close()
    sample:=sampleFrame()
    start:=Frame{Kind:Start,SourceID:sample.SourceID,GenerationID:sample.GenerationID,
        ReceiptSHA256:sample.ReceiptSHA256,Sequence:1,
        BatchIDs:[]string{"batch-1"},ExpectedRecords:2}
    if err:=client.Send(context.Background(),start);err!=nil{t.Fatal(err)}
    pipeline,err:=NewClientPipeline(context.Background(),client,4)
    if err!=nil{t.Fatal(err)}
    defer pipeline.Close()
    first:=sample
    first.Sequence=2
    ackFirst,err:=pipeline.Submit(context.Background(),first)
    if err!=nil{t.Fatal(err)}
    // A reporting group seal is a pure notification, not a flush of
    // the outstanding SourceParent or five-family SQL buffers.
    seal:=Frame{Kind:Seal,SourceID:sample.SourceID,
        GenerationID:sample.GenerationID,ReceiptSHA256:sample.ReceiptSHA256,
        Sequence:3,SealedGroup:1}
    if err:=pipeline.Send(context.Background(),seal);err!=nil{t.Fatal(err)}
    select{
    case <-ackFirst:t.Fatal("group seal illegally committed/flushed the first SQL job")
    default:
    }
    second:=sampleFrame()
    second.Sequence=4
    second.Rows[0].Ordinal=2
    ackSecond,err:=pipeline.Submit(context.Background(),second)
    if err!=nil{t.Fatal(err)}
    // If the server serialized COMMIT, it would never dispatch sequence 3
    // until sequence 2 completed; this proves C1's shared-pool behavior.
    for _,want:=range []uint64{2,4}{
        select{
        case got:=<-observed:
            if got!=want{t.Fatalf("source admission order %d expected %d",got,want)}
        case <-time.After(3*time.Second):
            t.Fatal("C1 SQL commit serialized before next family admission")
        }
    }
    close(releaseSecond)
    select{
    case err:=<-ackSecond:if err!=nil{t.Fatal(err)}
    case <-time.After(3*time.Second):t.Fatal("second COMMIT ACK did not arrive independently")
    }
    select{
    case <-ackFirst:t.Fatal("first SQL COMMIT acknowledged before release")
    case <-time.After(30*time.Millisecond):
    }
    close(releaseFirst)
    if err=<-ackFirst;err!=nil{t.Fatal(err)}
    if err=pipeline.WaitAll(context.Background());err!=nil{t.Fatal(err)}
    drain:=Frame{Kind:Drain,SourceID:sample.SourceID,GenerationID:sample.GenerationID,
        ReceiptSHA256:sample.ReceiptSHA256,Sequence:5}
    if err=pipeline.Send(context.Background(),drain);err!=nil{t.Fatal(err)}
    if err=<-serverDone;err!=nil{t.Fatal(err)}
}
func TestC1PipelineRejectsFailedSQLCommit(t *testing.T){
    serverFiles,clientFiles:=issueTestIdentity(t)
    serverTLS,_:=ServerTLSConfig(serverFiles,"fi-ingest.local")
    clientTLS,_:=ClientTLSConfig(clientFiles,"fi-sor.local")
    a,b:=net.Pipe()
    defer a.Close();defer b.Close()
    srv:=&Server{
        Bootstrap:func(context.Context,Frame)([]int64,error){return []int64{55},nil},
        Handler:func(context.Context,Frame)error{return nil},
        Dispatch:func(_ context.Context,f Frame)(<-chan error,error){
            result:=make(chan error,1)
            result<-errors.New("injected PostgreSQL commit failure")
            close(result)
            return result,nil
        },
        IOTimeout:5*time.Second,
    }
    go func(){_ =srv.ServeConn(context.Background(),tls.Server(a,serverTLS))}()
    c,e:=NewClient(tls.Client(b,clientTLS));if e!=nil{t.Fatal(e)}
    defer c.Close()
    sample:=sampleFrame()
    start:=Frame{Kind:Start,SourceID:sample.SourceID,GenerationID:sample.GenerationID,
        ReceiptSHA256:sample.ReceiptSHA256,Sequence:1,BatchIDs:[]string{"b"},ExpectedRecords:1}
    if e=c.Send(context.Background(),start);e!=nil{t.Fatal(e)}
    pipeline,e:=NewClientPipeline(context.Background(),c,4);if e!=nil{t.Fatal(e)}
    defer pipeline.Close()
    sample.Sequence=2
    future,e:=pipeline.Submit(context.Background(),sample);if e!=nil{t.Fatal(e)}
    select{
    case err:=<-future:
        if err==nil{t.Fatal("fi-sor failed SQL commit acknowledged")}
    case <-time.After(3*time.Second):t.Fatal("failed SQL commit ACK not delivered")
    }
    outcome:=pipeline.WaitAll(context.Background())
    if outcome==nil||!strings.Contains(outcome.Error(),"rejected"){
        t.Fatalf("C1 accepted failed SQL buffer as committed: %v",outcome)
    }
}
