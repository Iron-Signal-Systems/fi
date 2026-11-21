// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package c1handoff

import (
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
)

func issueTestIdentity(t *testing.T)(TLSFiles,TLSFiles){
    t.Helper()
    rootKey,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{t.Fatal(e)}
    root:=&x509.Certificate{SerialNumber:big.NewInt(1),
        Subject:pkix.Name{CommonName:"FI C1 test CA"},
        NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),
        IsCA:true,BasicConstraintsValid:true,KeyUsage:x509.KeyUsageCertSign,
    }
    rootDER,e:=x509.CreateCertificate(rand.Reader,root,root,&rootKey.PublicKey,rootKey)
    if e!=nil{t.Fatal(e)}
    rootCert,e:=x509.ParseCertificate(rootDER);if e!=nil{t.Fatal(e)}
    dir:=t.TempDir()
    ca:=filepath.Join(dir,"ca.pem")
    if e=os.WriteFile(ca,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:rootDER}),0600);e!=nil{t.Fatal(e)}
    makeLeaf:=func(name string,usage x509.ExtKeyUsage)TLSFiles{
        t.Helper()
        key,e:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader);if e!=nil{t.Fatal(e)}
        leaf:=&x509.Certificate{SerialNumber:big.NewInt(int64(len(name)+2)),
            Subject:pkix.Name{CommonName:name},DNSNames:[]string{name},
            NotBefore:time.Now().Add(-time.Hour),NotAfter:time.Now().Add(time.Hour),
            ExtKeyUsage:[]x509.ExtKeyUsage{usage},KeyUsage:x509.KeyUsageDigitalSignature,
        }
        der,e:=x509.CreateCertificate(rand.Reader,leaf,rootCert,&key.PublicKey,rootKey)
        if e!=nil{t.Fatal(e)}
        crt:=filepath.Join(dir,name+".crt")
        keypath:=filepath.Join(dir,name+".key")
        kb,e:=x509.MarshalECPrivateKey(key);if e!=nil{t.Fatal(e)}
        if e=os.WriteFile(crt,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),0600);e!=nil{t.Fatal(e)}
        if e=os.WriteFile(keypath,pem.EncodeToMemory(&pem.Block{Type:"EC PRIVATE KEY",Bytes:kb}),0600);e!=nil{t.Fatal(e)}
        return TLSFiles{Certificate:crt,PrivateKey:keypath,TrustCA:ca}
    }
    return makeLeaf("fi-sor.local",x509.ExtKeyUsageServerAuth),
        makeLeaf("fi-ingest.local",x509.ExtKeyUsageClientAuth)
}
func TestC1MutualTLSAndCommitAcknowledgment(t *testing.T){
    serverFiles,clientFiles:=issueTestIdentity(t)
    tlsServer,e:=ServerTLSConfig(serverFiles,"fi-ingest.local");if e!=nil{t.Fatal(e)}
    tlsClient,e:=ClientTLSConfig(clientFiles,"fi-sor.local");if e!=nil{t.Fatal(e)}
    rawServer,rawClient:=net.Pipe()
    defer rawServer.Close();defer rawClient.Close()
    committed:=make(chan struct{})
    entered:=make(chan struct{})
    serverDone:=make(chan error,1)
    srv:=&Server{Bootstrap:func(_ context.Context,f Frame)([]int64,error){
        if f.Kind!=Start||len(f.BatchIDs)!=1||f.BatchIDs[0]!="original-batch-1"{
            return nil,errors.New("invalid signed Start manifest")
        }
        return []int64{10},nil
    },Handler:func(_ context.Context,f Frame)error{
        if f.Kind==Source{
            close(entered)
            <-committed // Simulates waiting for PostgreSQL COMMIT ACK
        }
        return nil
    },IOTimeout:10*time.Second}
    go func(){serverDone<-srv.ServeConn(context.Background(),tls.Server(rawServer,tlsServer))}()
    c,e:=NewClient(tls.Client(rawClient,tlsClient));if e!=nil{t.Fatal(e)}
    defer c.Close()
    f:=sampleFrame()
    start:=Frame{Kind:Start,SourceID:f.SourceID,
        GenerationID:f.GenerationID,ReceiptSHA256:f.ReceiptSHA256,
        Sequence:1,BatchIDs:[]string{"original-batch-1"},ExpectedRecords:1}
    if err:=c.Send(context.Background(),start);err!=nil{t.Fatal(err)}
    if ids:=c.BatchSQLIDs();len(ids)!=1||ids[0]!=10{
        t.Fatalf("SoR original signed batch SQL mapping missing: %v",ids)
    }
    f.Sequence=2
    sent:=make(chan error,1)
    go func(){sent<-c.Send(context.Background(),f)}()
    select{case <-entered:case <-time.After(5*time.Second):t.Fatal("SoR did not receive signed buffer")}
    select{case <-sent:t.Fatal("SQL commit ACK was sent before COMMIT")
        case <-time.After(30*time.Millisecond):}
    close(committed)
    if e:=<-sent;e!=nil{t.Fatal(e)}
    done:=Frame{Kind:Drain,SourceID:f.SourceID,GenerationID:f.GenerationID,
        ReceiptSHA256:f.ReceiptSHA256,Sequence:3}
    if e=c.Send(context.Background(),done);e!=nil{t.Fatal(e)}
    if e=<-serverDone;e!=nil{t.Fatal(e)}
}
func TestC1ServerRejectsWrongClientIdentity(t *testing.T){
    serverFiles,clientFiles:=issueTestIdentity(t)
    config,e:=ServerTLSConfig(serverFiles,"not-the-ingest-jail.local");if e!=nil{t.Fatal(e)}
    client,e:=ClientTLSConfig(clientFiles,"fi-sor.local");if e!=nil{t.Fatal(e)}
    // A TCP socket has OS buffering for the TLS alert. net.Pipe has no
    // buffering: a server that rejects the client cert can deadlock writing
    // the alert after the client stops reading its handshake.
    listener,err:=net.Listen("tcp4","127.0.0.1:0")
    if err!=nil{t.Fatal(err)}
    defer listener.Close()
    serverErr:=make(chan error,1)
    go func(){
        raw,e:=listener.Accept()
        if e!=nil{serverErr<-e;return}
        defer raw.Close()
        _=raw.SetDeadline(time.Now().Add(3*time.Second))
        serverErr<-ensureAuthenticated(tls.Server(raw,config))
    }()
    conn,clientErr:=tls.DialWithDialer(&net.Dialer{Timeout:3*time.Second},
        "tcp4",listener.Addr().String(),client)
    if conn!=nil{_ =conn.Close()}
    select{
    case err:=<-serverErr:
        if err==nil||!strings.Contains(err.Error(),"unexpected fi-ingest identity"){
            t.Fatalf("unapproved client SAN was not rejected: %v",err)
        }
        // The client also cannot complete an authorized C1 session.
        if clientErr==nil{t.Fatal("client authenticated against rejecting server")}
    case <-time.After(4*time.Second):
        t.Fatal("C1 rejected-client TLS handshake deadlocked")
    }
}
func TestC1ServerRejectsPlaintext(t *testing.T){
    a,b:=net.Pipe()
    defer a.Close();defer b.Close()
    if err:=ensureAuthenticated(a);err==nil{
        t.Fatal("plaintext inter-jail SQL handoff was allowed")
    }
    var f Frame
    if errors.Is(f.Validate(),nil){t.Fatal("empty SQL frame accepted")}
}
