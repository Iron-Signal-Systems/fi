// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package c1handoff

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "errors"
    "fmt"
    "net"
    "os"
    "time"
)

const ALPN = "fi-c1/1"

// Each jail uses a distinct certificate with a DNS SAN. The fi-ingest jail
// gets only its client identity; the fi-sor jail owns the server private key.
// Neither a plain TCP connection nor an unverified peer can carry C1 records.
type TLSFiles struct {
    Certificate string
    PrivateKey string
    TrustCA string
}
func loadIdentity(files TLSFiles) (tls.Certificate,*x509.CertPool,error){
    if files.Certificate==""||files.PrivateKey==""||files.TrustCA==""{
        return tls.Certificate{},nil,errors.New("C1 mTLS: certificate, key and CA trust are required")
    }
    cert,err:=tls.LoadX509KeyPair(files.Certificate,files.PrivateKey)
    if err!=nil{return tls.Certificate{},nil,err}
    data,err:=os.ReadFile(files.TrustCA)
    if err!=nil{return tls.Certificate{},nil,err}
    pool:=x509.NewCertPool()
    if !pool.AppendCertsFromPEM(data){return tls.Certificate{},nil,errors.New("C1 mTLS: empty/untrusted CA")}
    return cert,pool,nil
}
func hasSAN(cert *x509.Certificate,want string)bool{
    if cert==nil||want==""{return false}
    for _,dns:=range cert.DNSNames{if dns==want{return true}}
    return false
}
func ServerTLSConfig(files TLSFiles,clientDNS string)(*tls.Config,error){
    cert,ca,err:=loadIdentity(files)
    if err!=nil{return nil,err}
    if clientDNS==""{return nil,errors.New("C1 mTLS: expected fi-ingest client SAN required")}
    return &tls.Config{
        MinVersion:tls.VersionTLS13,MaxVersion:tls.VersionTLS13,
        ClientAuth:tls.RequireAndVerifyClientCert,ClientCAs:ca,
        Certificates:[]tls.Certificate{cert},NextProtos:[]string{ALPN},
        VerifyConnection:func(s tls.ConnectionState)error{
            if len(s.VerifiedChains)==0||len(s.PeerCertificates)==0||
                !hasSAN(s.PeerCertificates[0],clientDNS){
                return errors.New("C1 mTLS: unexpected fi-ingest identity")
            }
            return nil
        },
    },nil
}
func ClientTLSConfig(files TLSFiles,serverDNS string)(*tls.Config,error){
    cert,ca,err:=loadIdentity(files)
    if err!=nil{return nil,err}
    if serverDNS==""{return nil,errors.New("C1 mTLS: expected fi-sor server SAN required")}
    return &tls.Config{
        MinVersion:tls.VersionTLS13,MaxVersion:tls.VersionTLS13,
        ServerName:serverDNS,RootCAs:ca,
        Certificates:[]tls.Certificate{cert},NextProtos:[]string{ALPN},
    },nil
}

// Every accepted request must finish a PostgreSQL transaction *inside*
// fi-sor before it returns nil. A successfully queued buffer is not a
// commit. Independent verification is scheduled outside this handler.
type CommitHandler func(context.Context,Frame)error
// Bootstrap is executed only for the first original signed Start request.
// The fi-sor jail must prove these names against its preexisting private
// relational source-batch ledger BEFORE returning any SQL identities.
type BootstrapHandler func(context.Context,Frame)([]int64,error)

type Server struct {
    Handler CommitHandler
    Bootstrap BootstrapHandler
    // When configured, SQL source/family work is enqueued into the native
    // fi-sor C1 pool without blocking the network reader. Each future
    // resolves only after its own PostgreSQL transaction commits.
    Dispatch func(context.Context,Frame)(<-chan error,error)
    // Called ONLY after Drain's SQL and independent verifier handler
    // succeeded. A real canonical Accepted transaction must complete
    // before this callback can return FinalAccepted. Nil is SQL-only.
    FinalProof func(context.Context,Frame)(FinalStatus,error)
    IOTimeout time.Duration
}
func ensureAuthenticated(conn net.Conn)error{
    c,ok:=conn.(*tls.Conn)
    if !ok{return errors.New("C1 handoff: unencrypted TCP prohibited")}
    if err:=c.Handshake();err!=nil{return err}
    state:=c.ConnectionState()
    if state.Version!=tls.VersionTLS13||state.NegotiatedProtocol!=ALPN||
        len(state.VerifiedChains)==0||len(state.PeerCertificates)==0{
        return errors.New("C1 handoff: verified TLS 1.3 peer and protocol required")
    }
    return nil
}
func (s *Server) ServeConn(ctx context.Context,conn net.Conn)error{
    if ctx==nil||conn==nil||s==nil||s.Handler==nil||s.Bootstrap==nil{return errors.New("C1 handoff: invalid server")}
    defer conn.Close()
    if err:=ensureAuthenticated(conn);err!=nil{return fmt.Errorf("C1 handoff: TLS: %w",err)}
    idle:=s.IOTimeout
    if idle<=0{idle=5*time.Minute}
    var source,generation,receipt string
    var sequence uint64=1
    for {
        if err:=ctx.Err();err!=nil{return err}
        if err:=conn.SetReadDeadline(time.Now().Add(idle));err!=nil{return err}
        f,err:=ReadFrame(conn)
        if err!=nil{return err}
        if f.Kind==Ack{return errors.New("C1 handoff: client sent server-only acknowledgment")}
        if sequence==1 {
            if f.Kind!=Start{return errors.New("C1 handoff: signed generation Start must precede SQL handoffs")}
            source,generation,receipt=f.SourceID,f.GenerationID,f.ReceiptSHA256
        }else if f.Kind==Start{
            return errors.New("C1 handoff: repeated signed generation Start")
        }else if f.SourceID!=source||f.GenerationID!=generation||f.ReceiptSHA256!=receipt {
            return errors.New("C1 handoff: session source or signed receipt changed")
        }
        if f.Sequence!=sequence{return errors.New("C1 handoff: reordered/duplicated request")}
        if err:=conn.SetReadDeadline(time.Time{});err!=nil{return err}
        // C1 Start resolves exact signed batch IDs in the local fi-sor
        // database; ordinary messages execute the real C1 SQL pool.
        var commitErr error
        var sourceBatchIDs []int64
        if f.Kind==Start{
            sourceBatchIDs,commitErr=s.Bootstrap(ctx,f)
            if commitErr==nil && len(sourceBatchIDs)!=len(f.BatchIDs){
                commitErr=errors.New("C1 fi-sor: incomplete source-batch SQL identity map")
            }
        }else{
            // Validation process B remains separate and parallel. A SQL
            // ACK is emitted only after THIS buffer is durably committed.
            commitErr=s.Handler(ctx,f)
        }
        var finalStatus FinalStatus
        if f.Kind==Drain && commitErr==nil && s.FinalProof!=nil {
            finalStatus,commitErr=s.FinalProof(ctx,f)
        }
        ack:=Frame{Kind:Ack,SourceID:source,GenerationID:generation,
            ReceiptSHA256:receipt,Sequence:sequence,Committed:commitErr==nil,
            FinalStatus:finalStatus}
        if commitErr!=nil {ack.Error="C1 fi-sor SQL processing rejected handoff"
        }else if f.Kind==Start {ack.BatchSQLIDs=sourceBatchIDs}
        if err:=conn.SetWriteDeadline(time.Now().Add(idle));err!=nil{return err}
        if err:=WriteFrame(conn,ack);err!=nil{return err}
        if commitErr!=nil{return fmt.Errorf("C1 handoff: backend commit failed: %w",commitErr)}
        if f.Kind==Drain {return nil}
        sequence++
        if f.Kind==Start && s.Dispatch!=nil {
            return s.servePipelined(ctx,conn,source,generation,receipt,sequence,idle)
        }
    }
}
type Client struct{
    conn net.Conn
    next uint64
    source,generation,receipt string
    batchIDs []int64
}
func NewClient(conn net.Conn)(*Client,error){
    if conn==nil{return nil,errors.New("C1 handoff: missing connection")}
    if err:=ensureAuthenticated(conn);err!=nil{return nil,err}
    return &Client{conn:conn,next:1},nil
}
func (c *Client)Send(ctx context.Context,f Frame)error{
    if c==nil||c.conn==nil||ctx==nil{return errors.New("C1 handoff: missing authenticated session")}
    if err:=ctx.Err();err!=nil{return err}
    if f.Kind==Ack||f.Sequence!=c.next{return errors.New("C1 handoff: bad next client sequence")}
    if c.next==1 && f.Kind!=Start{return errors.New("C1 handoff: signed Start required before SQL")}
    if c.next>1 && f.Kind==Start{return errors.New("C1 handoff: duplicate signed Start")}
    if c.next>1 &&
        (f.SourceID!=c.source||f.GenerationID!=c.generation||f.ReceiptSHA256!=c.receipt){
        return errors.New("C1 handoff: client switched signed generation")
    }
    // No automatic reconnect/replay on an uncertain SQL COMMIT. Recovery
    // must first reconcile against immutable signed custody and staged SQL.
    if err:=WriteFrame(c.conn,f);err!=nil{return err}
    reply,err:=ReadFrame(c.conn)
    if err!=nil{return fmt.Errorf("C1 handoff: SQL commit uncertain; reconcile before retry: %w",err)}
    if reply.Kind!=Ack||reply.Sequence!=f.Sequence||
        reply.ReceiptSHA256!=f.ReceiptSHA256||reply.SourceID!=f.SourceID||
        reply.GenerationID!=f.GenerationID ||
        (reply.FinalStatus!=FinalNone && f.Kind!=Drain) {
        return errors.New("C1 handoff: wrong signed generation/sequence ACK")
    }
    if !reply.Committed{return fmt.Errorf("C1 handoff: fi-sor rejected signed buffer: %s",reply.Error)}
    if f.Kind==Start{
        if len(reply.BatchSQLIDs)!=len(f.BatchIDs){
            return errors.New("C1 handoff: incomplete fi-sor signed source-batch SQL mapping")
        }
        c.batchIDs=append([]int64(nil),reply.BatchSQLIDs...)
    }else if len(reply.BatchSQLIDs)!=0{
        return errors.New("C1 handoff: unexpected SQL batch IDs outside Start ACK")
    }
    if c.next==1 {c.source,c.generation,c.receipt=f.SourceID,f.GenerationID,f.ReceiptSHA256}
    c.next++
    return nil
}
// BatchSQLIDs is available only after fi-sor proved the Start manifest
// list against its local private relational source-batch records.
func(c *Client)BatchSQLIDs()[]int64{
    if c==nil{return nil}
    return append([]int64(nil),c.batchIDs...)
}
func(c *Client)Close()error{
    if c==nil||c.conn==nil{return nil}
    return c.conn.Close()
}
