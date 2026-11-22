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
func TestC1AuthenticatedReadOnlyStatusBeforeStart(t *testing.T){
    for _,tc:=range []struct{name string; status FinalStatus; fail bool}{
        {"not-yet-accepted",FinalNone,false},
        {"canonical-Accepted",FinalAccepted,false},
        {"B-only-cannot-answer-status",FinalVerified,true},
    }{
        t.Run(tc.name,func(t *testing.T){
            srvCert,cliCert:=issueTestIdentity(t)
            tlsServer,e:=ServerTLSConfig(srvCert,"fi-ingest.local")
            if e!=nil{t.Fatal(e)}
            tlsClient,e:=ClientTLSConfig(cliCert,"fi-sor.local")
            if e!=nil{t.Fatal(e)}
            // Use a real TCP socket, not unbuffered net.Pipe:
            // TLS 1.3 CloseNotify on both ends of net.Pipe can block
            // forever after a successful one-shot status response.
            listener,e:=net.Listen("tcp4","127.0.0.1:0")
            if e!=nil{t.Fatal(e)}
            defer listener.Close()
            done:=make(chan error,1)
            srv:=&Server{
                IOTimeout:5*time.Second,
                Status:func(_ context.Context,f Frame)(FinalStatus,error){
                    if f.Kind!=Status||f.Sequence!=1||
                       f.SourceID!="source.example"||f.GenerationID!="generation-1"{
                        return FinalNone,errors.New("foreign untrusted source")
                    }
                    return tc.status,nil
                },
                Bootstrap:func(context.Context,Frame)([]int64,error){
                    t.Fatal("read-only status must not start private C1 SQL or source-ledger bootstrap")
                    return nil,errors.New("wrong path")
                },
                Handler:func(context.Context,Frame)error{
                    t.Fatal("read-only status must not execute C1 SQL")
                    return errors.New("wrong path")
                },
            }
            go func(){
                peer,e:=listener.Accept()
                if e!=nil{done<-e;return}
                done<-srv.ServeConn(context.Background(),tls.Server(peer,tlsServer))
            }()
            raw,e:=net.DialTimeout("tcp4",listener.Addr().String(),3*time.Second)
            if e!=nil{t.Fatal(e)}
            client,e:=NewClient(tls.Client(raw,tlsClient))
            if e!=nil{t.Fatal(e)}
            defer client.Close()
            frame:=Frame{Kind:Status,Sequence:1,SourceID:"source.example",
                GenerationID:"generation-1",ReceiptSHA256:strings.Repeat("a",64)}
            ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
            defer cancel()
            accepted,err:=client.QueryStatus(ctx,frame)
            if tc.fail{
                if err==nil||accepted{t.Fatal("SoR falsely claimed unverified B as canonical Accepted")}
            }else if err!=nil||accepted!=(tc.status==FinalAccepted){
                t.Fatalf("canonical status=%d accepted=%t err=%v",tc.status,accepted,err)
            }
            select{
            case e=<-done:
                if tc.fail{
                    if e==nil{t.Fatal("SoR returned successful B-only status")}
                }else if e!=nil{t.Fatalf("read-only SoR status failed: %v",e)}
            case <-ctx.Done():t.Fatal("read-only C1 status protocol hung")
            }
        })
    }
}
func TestC1StatusRequiresNewClientAndExactIdentity(t *testing.T){
    c:=&Client{next:2}
    frame:=Frame{Kind:Status,SourceID:"a",GenerationID:"b",
        ReceiptSHA256:strings.Repeat("a",64),Sequence:1}
    if _,err:=c.QueryStatus(context.Background(),frame);err==nil{
        t.Fatal("status probe was accepted after a START session")
    }
    f:=sampleFrame()
    f.Kind=Status;f.Rows=nil
    if err:=f.Validate();err!=nil{t.Fatalf("valid read-only Status frame rejected: %v",err)}
    f.Rows=sampleFrame().Rows
    if err:=f.Validate();err==nil{t.Fatal("status carried source rows without SQL authentication")}
}
