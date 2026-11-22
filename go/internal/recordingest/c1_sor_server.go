//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "crypto/tls"
    "errors"
    "fmt"
    "net"
    "strings"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)

type C1SoRServerConfig struct {
    Bind string
    LocalPostgresDSN string
    PublisherPostgresDSN string // separate canonical locking authority, Unix socket only
    SQLWorkersMax int
    SharedRAMDir string // read-only fi-sor nullfs mount
    AllowC1Replay bool // development-only private SQL recovery opt-in
    CustodyRoot string // original signed receiver custody, read-only
    RecordedRoot string // immutable signed recorded receipts, read-only
    CustodySourceNamespaces bool
    MaxCanonicalBytes uint64
    MaxEncodedBytes uint64
    MaxManifestBytes uint64
    TransportCert c1handoff.TLSFiles
    ExpectedIngestClientDNS string
}
// PreflightC1SoRWorker checks the EXACT production startup prerequisites
// without listening, writing PostgreSQL, starting verifier B, or accepting
// a generation. The live worker uses the same validation routine.
func PreflightC1SoRWorker(ctx context.Context,cfg C1SoRServerConfig)error{
    _,err:=c1SoRStartupTLS(ctx,cfg)
    return err
}
func c1SoRStartupTLS(ctx context.Context,cfg C1SoRServerConfig)(*tls.Config,error){
    if ctx==nil{return nil,errors.New("C1 fi-sor: context required")}
    if cfg.SQLWorkersMax<1||cfg.SQLWorkersMax>32{
        return nil,errors.New("C1 fi-sor: native SQL worker count must be 1..32")
    }
    if cfg.CustodyRoot==""||cfg.RecordedRoot==""||cfg.SharedRAMDir==""{
        return nil,errors.New("C1 fi-sor: original signed custody and shared RAM required")
    }
    host,port,err:=net.SplitHostPort(cfg.Bind)
    if err!=nil||host==""||port==""||strings.HasPrefix(cfg.Bind,":"){
        return nil,errors.New("C1 fi-sor: explicit private jail bind IP and port required")
    }
    address:=net.ParseIP(host)
    if address==nil||address.IsUnspecified()||address.IsLoopback()||address.IsMulticast(){
        return nil,errors.New("C1 fi-sor: private jail address must be explicit and nonlocal")
    }
    if _,err=c1SoRLocalConnectionConfig(cfg.LocalPostgresDSN);err!=nil{return nil,err}
    if _,err=c1SoRLocalPublisherConfig(cfg.PublisherPostgresDSN);err!=nil{return nil,err}
    // Both SQL roles and the governed Pending ACL graph are checked
    // READ ONLY against the existing local socket before any TLS listener.
    if err=c1PreflightLocalGovernedPendingSQL(ctx,cfg.LocalPostgresDSN);err!=nil{
        return nil,fmt.Errorf("C1 fi-sor: SQL worker/Pending admission not ready: %w",err)
    }
    if err=c1PreflightLocalPublisher(ctx,cfg.PublisherPostgresDSN);err!=nil{
        return nil,fmt.Errorf("C1 fi-sor: canonical publisher not ready: %w",err)
    }
    // Pin the real server certificate and allowed fi-ingest client identity.
    tlsConfig,err:=c1handoff.ServerTLSConfig(cfg.TransportCert,cfg.ExpectedIngestClientDNS)
    if err!=nil{return nil,err}
    return tlsConfig,nil
}
func RunC1SoRWorker(ctx context.Context,cfg C1SoRServerConfig)error{
    tlsConfig,err:=c1SoRStartupTLS(ctx,cfg)
    if err!=nil{return err}
    listen,err:=tls.Listen("tcp4",cfg.Bind,tlsConfig)
    if err!=nil{return fmt.Errorf("C1 fi-sor: bind private handoff listener: %w",err)}
    defer listen.Close()
    // Close listener on signal cancellation without leaving a blocking
    // Accept; no restart or publication task is spawned asynchronously.
    closeDone:=make(chan struct{})
    go func(){select{case <-ctx.Done():_ = listen.Close();case <-closeDone:}}()
    defer close(closeDone)
    for {
        conn,err:=listen.Accept()
        if err!=nil{
            if ctx.Err()!=nil{return nil}
            return fmt.Errorf("C1 fi-sor: authenticated listener failed: %w",err)
        }
        // One generation at a time, preserving the native ordered SQL
        // writer's session ownership and preventing concurrent replays.
        service,e:=NewC1SoRService(cfg.LocalPostgresDSN,cfg.SQLWorkersMax)
        if e!=nil{conn.Close();return e}
        service.SharedRAMDir=cfg.SharedRAMDir
        service.PublisherDSN=cfg.PublisherPostgresDSN
        service.AllowC1Replay=cfg.AllowC1Replay
        service.NativeBCustody=c1NativeBCustodyConfig{
            CustodyRoot:cfg.CustodyRoot,RecordedRoot:cfg.RecordedRoot,
            SourceNamespaces:cfg.CustodySourceNamespaces,
            MaxCanonicalBytes:cfg.MaxCanonicalBytes,
            MaxEncodedBytes:cfg.MaxEncodedBytes,
            MaxManifestBytes:cfg.MaxManifestBytes,
        }
        endpoint:=&c1handoff.Server{
            Bootstrap:service.Bootstrap,Handler:service.Commit,
            Dispatch:service.Dispatch,FinalProof:service.FinalProof,
            // Status runs before START and never initializes private SQL
            // staging or any C1 worker. It only reads ORIGINAL receiver
            // receipt and canonical Accepted transaction on the local SoR.
            Status:func(ctx context.Context,f c1handoff.Frame)(
                c1handoff.FinalStatus,error,
            ){
                return C1OriginalSignedStatus(ctx,cfg.LocalPostgresDSN,
                    service.NativeBCustody,f)
            },
            IOTimeout:5*time.Minute,
        }
        e=endpoint.ServeConn(ctx,conn)
        service.Close()
        if e!=nil && ctx.Err()==nil {
            // A failed/uncertain transaction requires staging reconciliation.
            // The next START preflight will reject any dirty source/typed
            // projection, never erase or replay it automatically.
            fmt.Printf("FI C1 SOR SESSION STOP error=%v preserve_canonical=true auto_replay=false\n",e)
        }
        if ctx.Err()!=nil{return nil}
    }
}
