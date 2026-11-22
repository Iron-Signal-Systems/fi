//go:build fi_c1_sor_dev && !windows

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Real TLS 1.3 client -> server -> prepared C1 tmpfs -> independent per-buffer
// SQL COMMIT future -> producer RAM reclamation. This uses the original C1
// producer sink and the real 64-credit mTLS pipeline. The fake SQL future
// deliberately delays commits, so no row is reported durable on admission.
// PostgreSQL semantics are independently checked in the PG18 fixture.
package recordingest

import (
    "bytes"
    "context"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "errors"
    "math/big"
    "net"
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)

func issueC1MTLSRAMTestIdentity(t *testing.T)(
    c1handoff.TLSFiles,c1handoff.TLSFiles,
){
    t.Helper()
    rootKey,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
    if err!=nil{t.Fatal(err)}
    root:=&x509.Certificate{SerialNumber:big.NewInt(1),
        Subject:pkix.Name{CommonName:"C1 RAM integration test CA"},
        NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),
        IsCA:true,BasicConstraintsValid:true,KeyUsage:x509.KeyUsageCertSign}
    rootDER,err:=x509.CreateCertificate(rand.Reader,root,root,&rootKey.PublicKey,rootKey)
    if err!=nil{t.Fatal(err)}
    rootCert,err:=x509.ParseCertificate(rootDER)
    if err!=nil{t.Fatal(err)}
    dir:=t.TempDir()
    ca:=filepath.Join(dir,"ca.pem")
    if err=os.WriteFile(ca,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:rootDER}),0600);err!=nil{
        t.Fatal(err)
    }
    issue:=func(dns string,usage x509.ExtKeyUsage)c1handoff.TLSFiles{
        t.Helper()
        key,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
        if e!=nil{t.Fatal(e)}
        leaf:=&x509.Certificate{SerialNumber:big.NewInt(int64(2+len(dns))),
            Subject:pkix.Name{CommonName:dns},DNSNames:[]string{dns},
            NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),
            KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{usage}}
        der,e:=x509.CreateCertificate(rand.Reader,leaf,rootCert,&key.PublicKey,rootKey)
        if e!=nil{t.Fatal(e)}
        keyDER,e:=x509.MarshalECPrivateKey(key)
        if e!=nil{t.Fatal(e)}
        certPath:=filepath.Join(dir,dns+".crt")
        keyPath:=filepath.Join(dir,dns+".key")
        if e=os.WriteFile(certPath,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),0600);e!=nil{t.Fatal(e)}
        if e=os.WriteFile(keyPath,pem.EncodeToMemory(&pem.Block{Type:"EC PRIVATE KEY",Bytes:keyDER}),0600);e!=nil{t.Fatal(e)}
        return c1handoff.TLSFiles{Certificate:certPath,PrivateKey:keyPath,TrustCA:ca}
    }
    return issue("fi-sor.local",x509.ExtKeyUsageServerAuth),
        issue("fi-ingest.local",x509.ExtKeyUsageClientAuth)
}
func TestC1RealMTLSPipelinePreservesPreparedRAMUntilOwnCommitACK(t *testing.T){
    store:=c1RAMTestStore(t)
    serverCert,clientCert:=issueC1MTLSRAMTestIdentity(t)
    serverTLS,err:=c1handoff.ServerTLSConfig(serverCert,"fi-ingest.local")
    if err!=nil{t.Fatal(err)}
    clientTLS,err:=c1handoff.ClientTLSConfig(clientCert,"fi-sor.local")
    if err!=nil{t.Fatal(err)}
    serverSocket,clientSocket:=net.Pipe()
    defer serverSocket.Close()
    defer clientSocket.Close()
    sourceGate:=make(chan struct{})
    typedGate:=make(chan struct{})
    observed:=make(chan c1handoff.Frame,2)
    serverDone:=make(chan error,1)
    original:=c1SQLTestFrame(c1handoff.Source,1)
    prepared,err:=PrepareSourceRecord(original.Rows[0].RawRecord)
    if err!=nil{t.Fatal(err)}
    signed:=privateP6Record{signedBatchIndex:0,sourceBatchID:55,ordinal:1,prepared:prepared}
    sourceID:="iss-fs-22a.iss.local"
    generation:="generation-test"
    receipt:=strings.Repeat("b",64)
    srv:=&c1handoff.Server{
        IOTimeout:5*time.Second,
        Bootstrap:func(_ context.Context,f c1handoff.Frame)([]int64,error){
            if f.Kind!=c1handoff.Start||f.Sequence!=1||f.SourceID!=sourceID||
                f.GenerationID!=generation||len(f.BatchIDs)!=1||
                f.BatchIDs[0]!="original-batch-1"{
                return nil,errors.New("C1 RAM: wrong signed original START")
            }
            return []int64{55},nil
        },
        Handler:func(_ context.Context,f c1handoff.Frame)error{
            if f.Kind!=c1handoff.Drain{return errors.New("unexpected C1 synchronous request")}
            return nil
        },
        // Simulate completed independent B, never canonical publication.
        FinalProof:func(_ context.Context,f c1handoff.Frame)(c1handoff.FinalStatus,error){
            if f.Kind!=c1handoff.Drain{return c1handoff.FinalNone,errors.New("wrong proof frame")}
            return c1handoff.FinalVerified,nil
        },
        Dispatch:func(ctx context.Context,f c1handoff.Frame)(<-chan error,error){
            if f.Shared.Name==""||len(f.Rows)!=0||f.Shared.Rows!=1{
                return nil,errors.New("C1 RAM: inline source incorrectly used after P5")
            }
            data,e:=store.Get(f.Shared)
            if e!=nil{return nil,e}
            rows,e:=decodeC1PreparedRAMRows(data)
            if e!=nil{return nil,e}
            if len(rows)!=1||rows[0].sourceBatchID!=55||rows[0].ordinal!=1||
                !bytes.Equal(rows[0].prepared.RawRecordBytes,prepared.RawRecordBytes)||
                rows[0].prepared.RecordDigest!=prepared.RecordDigest{
                return nil,errors.New("C1 RAM: prepared original SourceParent identity changed")
            }
            var gate <-chan struct{}
            switch f.Kind{
            case c1handoff.Source:gate=sourceGate
            case c1handoff.Other:gate=typedGate
            default:return nil,errors.New("C1 RAM: wrong family across jail")
            }
            observed<-f
            future:=make(chan error,1)
            go func(){
                select{
                case <-gate:future<-nil
                case <-ctx.Done():future<-ctx.Err()
                }
                close(future)
            }()
            return future,nil
        },
    }
    go func(){serverDone<-srv.ServeConn(context.Background(),tls.Server(serverSocket,serverTLS))}()
    client,err:=c1handoff.NewClient(tls.Client(clientSocket,clientTLS))
    if err!=nil{t.Fatal(err)}
    defer client.Close()
    ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
    defer cancel()
    start:=c1handoff.Frame{Kind:c1handoff.Start,SourceID:sourceID,
        GenerationID:generation,ReceiptSHA256:receipt,Sequence:1,
        ExpectedRecords:1,BatchIDs:[]string{"original-batch-1"}}
    if err=client.Send(ctx,start);err!=nil{t.Fatal(err)}
    if ids:=client.BatchSQLIDs();len(ids)!=1||ids[0]!=55{
        t.Fatalf("original signed fi-sor SQL batch identity lost: %v",ids)
    }
    pipeline,err:=c1handoff.NewClientPipeline(ctx,client,4)
    if err!=nil{t.Fatal(err)}
    defer pipeline.Close()
    remote,err:=newC1RemoteSoRSink(pipeline,sourceID,generation,receipt)
    if err!=nil{t.Fatal(err)}
    remote.next=2
    if err=remote.EnableSharedRAM(store);err!=nil{t.Fatal(err)}
    if err=remote.Source(ctx,[]privateP6Record{signed});err!=nil{t.Fatal(err)}
    if err=remote.Family(ctx,privateP6Other,[]privateP6Record{signed});err!=nil{t.Fatal(err)}
    first,second:=c1handoff.Frame{},c1handoff.Frame{}
    select{case first=<-observed:case <-ctx.Done():t.Fatal("SourceParent RAM never reached fi-sor")}
    select{case second=<-observed:case <-ctx.Done():t.Fatal("typed RAM never reached fi-sor")}
    if first.Kind!=c1handoff.Source||second.Kind!=c1handoff.Other||
        first.Sequence!=2||second.Sequence!=3{
        t.Fatal("original C1 SourceParent and Other SQL family reordered")
    }
    if _,err=store.Get(first.Shared);err!=nil{t.Fatal("source RAM freed before commit",err)}
    if _,err=store.Get(second.Shared);err!=nil{t.Fatal("typed RAM freed before commit",err)}
    close(typedGate)
    // The independent typed ACK must not free the still-uncommitted
    // SourceParent buffer. The producer's own cleanup goroutine owns ACKs.
    if _,err=store.Get(first.Shared);err!=nil{
        t.Fatal("SourceParent RAM disappeared before its own COMMIT",err)
    }
    close(sourceGate)
    if err=remote.WaitAll(ctx);err!=nil{t.Fatal(err)}
    if _,err=store.Get(first.Shared);!os.IsNotExist(err){
        t.Fatalf("confirmed parent SQL COMMIT did not release RAM: %v",err)
    }
    if _,err=store.Get(second.Shared);!os.IsNotExist(err){
        t.Fatalf("confirmed typed SQL COMMIT did not release RAM: %v",err)
    }
    if err=remote.Drain(ctx);err!=nil{t.Fatal(err)}
    if remote.finalStatus!=c1handoff.FinalVerified{
        t.Fatal("C1 signed B proof missing or SQL-only ACK incorrectly accepted")
    }
    select{
    case err=<-serverDone:
        if err!=nil{t.Fatal(err)}
    case <-ctx.Done():t.Fatal("C1 final two-jail SQL drain did not complete")
    }
}
