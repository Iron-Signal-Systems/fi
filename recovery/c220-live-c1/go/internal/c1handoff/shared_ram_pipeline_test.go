// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// A real, mutually authenticated TLS 1.3 C1 session passes only prepared
// tmpfs references through the sequence-checked inter-jail protocol. Each
// object stays in the producer store until its OWN out-of-order SQL COMMIT
// ACK. This test exercises the true socket pipeline, not just Frame codecs.
package c1handoff

import (
    "bytes"
    "context"
    "crypto/tls"
    "errors"
    "net"
    "os"
    "strings"
    "testing"
    "time"
)

func TestC1PreparedRAMAcrossTLSWithOutOfOrderCommitACKs(t *testing.T){
    dir:=t.TempDir()
    if err:=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
    store,err:=NewRAMStore(dir)
    if err!=nil{t.Fatal(err)}
    firstPayload:=[]byte("C1 prepared P5 Security source bytes with original checksum")
    secondPayload:=[]byte("C1 prepared P5 Other family bytes with original checksum")
    first,err:=store.Put(firstPayload,1)
    if err!=nil{t.Fatal(err)}
    second,err:=store.Put(secondPayload,1)
    if err!=nil{t.Fatal(err)}
    serverIdentity,clientIdentity:=issueTestIdentity(t)
    serverTLS,err:=ServerTLSConfig(serverIdentity,"fi-ingest.local")
    if err!=nil{t.Fatal(err)}
    clientTLS,err:=ClientTLSConfig(clientIdentity,"fi-sor.local")
    if err!=nil{t.Fatal(err)}
    left,right:=net.Pipe()
    defer left.Close()
    defer right.Close()
    releaseFirst:=make(chan struct{})
    releaseSecond:=make(chan struct{})
    observed:=make(chan uint64,2)
    serverFinished:=make(chan error,1)
    receipt:=strings.Repeat("a",64)
    srv:=&Server{
        IOTimeout:5*time.Second,
        Bootstrap:func(_ context.Context,f Frame)([]int64,error){
            if f.Kind!=Start||f.Sequence!=1||
                len(f.BatchIDs)!=1||f.BatchIDs[0]!="batch-original-1"{
                return nil,errors.New("unexpected signed C1 START plan")
            }
            return []int64{55},nil
        },
        Handler:func(_ context.Context,f Frame)error{
            if f.Kind!=Drain{return errors.New("unexpected synchronous SQL before final drain")}
            return nil
        },
        Dispatch:func(ctx context.Context,f Frame)(<-chan error,error){
            if len(f.Rows)!=0||f.Shared.Name==""{
                return nil,errors.New("raw records crossed the shared-memory-only jail boundary")
            }
            var want []byte
            var gate <-chan struct{}
            switch f.Sequence{
            case 2:
                if f.Kind!=Source{return nil,errors.New("wrong SourceParent family")}
                want=firstPayload
                gate=releaseFirst
            case 3:
                if f.Kind!=Other{return nil,errors.New("wrong typed SQL family")}
                want=secondPayload
                gate=releaseSecond
            default:
                return nil,errors.New("unexpected signed RAM transport sequence")
            }
            got,err:=store.Get(f.Shared)
            if err!=nil{return nil,err}
            if !bytes.Equal(want,got){
                return nil,errors.New("prepared bytes changed across RAM transport")
            }
            observed<-f.Sequence
            future:=make(chan error,1)
            go func(){
                select{
                case <-gate:
                    future<-nil // simulated durable PostgreSQL COMMIT
                case <-ctx.Done():
                    future<-ctx.Err()
                }
                close(future)
            }()
            return future,nil
        },
    }
    go func(){serverFinished<-srv.ServeConn(context.Background(),tls.Server(left,serverTLS))}()
    client,err:=NewClient(tls.Client(right,clientTLS))
    if err!=nil{t.Fatal(err)}
    defer client.Close()
    start:=Frame{Kind:Start,SourceID:"fi-test-source",
        GenerationID:"fi-test-generation",ReceiptSHA256:receipt,
        Sequence:1,BatchIDs:[]string{"batch-original-1"},ExpectedRecords:2}
    ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
    defer cancel()
    if err=client.Send(ctx,start);err!=nil{t.Fatal(err)}
    if ids:=client.BatchSQLIDs();len(ids)!=1||ids[0]!=55{
        t.Fatalf("original fi-sor batch mapping lost: %v",ids)
    }
    pipeline,err:=NewClientPipeline(ctx,client,4)
    if err!=nil{t.Fatal(err)}
    defer pipeline.Close()
    source:=Frame{Kind:Source,SourceID:start.SourceID,GenerationID:start.GenerationID,
        ReceiptSHA256:receipt,Sequence:2,Shared:first}
    typed:=Frame{Kind:Other,SourceID:start.SourceID,GenerationID:start.GenerationID,
        ReceiptSHA256:receipt,Sequence:3,Shared:second}
    one,err:=pipeline.Submit(ctx,source)
    if err!=nil{t.Fatal(err)}
    two,err:=pipeline.Submit(ctx,typed)
    if err!=nil{t.Fatal(err)}
    for _,expected:=range []uint64{2,3}{
        select{
        case actual:=<-observed:
            if actual!=expected{t.Fatalf("out-of-order SQL admission %d expected %d",actual,expected)}
        case <-ctx.Done():t.Fatal("fi-sor failed to read authenticated shared RAM payload")
        }
    }
    if _,err=store.Get(first);err!=nil{t.Fatal("fi-ingest reclaimed SourceParent before commit",err)}
    if _,err=store.Get(second);err!=nil{t.Fatal("fi-ingest reclaimed typed buffer before commit",err)}
    close(releaseSecond)
    select{
    case err=<-two:
        if err!=nil{t.Fatal(err)}
    case <-ctx.Done():t.Fatal("typed family SQL COMMIT ACK missing")
    }
    if err=store.Remove(second);err!=nil{t.Fatal(err)}
    if _,err=store.Get(first);err!=nil{
        t.Fatal("SourceParent RAM object lost before its separate COMMIT ACK",err)
    }
    select{
    case <-one:t.Fatal("SourceParent acknowledged without its SQL commit")
    default:
    }
    close(releaseFirst)
    select{
    case err=<-one:
        if err!=nil{t.Fatal(err)}
    case <-ctx.Done():t.Fatal("SourceParent SQL COMMIT ACK missing")
    }
    if err=store.Remove(first);err!=nil{t.Fatal(err)}
    if _,err=store.Get(first);!os.IsNotExist(err){
        t.Fatalf("committed SourceParent RAM object not reclaimed: %v",err)
    }
    if err=pipeline.WaitAll(ctx);err!=nil{t.Fatal(err)}
    drain:=Frame{Kind:Drain,SourceID:start.SourceID,
        GenerationID:start.GenerationID,ReceiptSHA256:receipt,Sequence:4}
    if err=pipeline.Send(ctx,drain);err!=nil{t.Fatal(err)}
    select{
    case err=<-serverFinished:
        if err!=nil{t.Fatal(err)}
    case <-ctx.Done():t.Fatal("fi-sor final drain failed to complete")
    }
}
