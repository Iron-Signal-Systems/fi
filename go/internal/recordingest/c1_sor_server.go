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
    SQLWorkersMax int
    TransportCert c1handoff.TLSFiles
    ExpectedIngestClientDNS string
}
func RunC1SoRWorker(ctx context.Context,cfg C1SoRServerConfig)error{
    if ctx==nil{return errors.New("C1 fi-sor: context required")}
    host,port,err:=net.SplitHostPort(cfg.Bind)
    if err!=nil||host==""||port==""||strings.HasPrefix(cfg.Bind,":"){
        return errors.New("C1 fi-sor: explicit private jail bind IP and port required")
    }
    address:=net.ParseIP(host)
    if address==nil||address.IsUnspecified()||address.IsLoopback()||address.IsMulticast(){
        return errors.New("C1 fi-sor: private jail address must be explicit and nonlocal")
    }
    if _,err=c1SoRLocalConnectionConfig(cfg.LocalPostgresDSN);err!=nil{return err}
    // mTLS requires the fi-ingest identity and the fi-sor dedicated server
    // certificate, independently issued under the configured C1 trust CA.
    tlsConfig,err:=c1handoff.ServerTLSConfig(cfg.TransportCert,cfg.ExpectedIngestClientDNS)
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
        endpoint:=&c1handoff.Server{
            Bootstrap:service.Bootstrap,Handler:service.Commit,
            Dispatch:service.Dispatch,IOTimeout:5*time.Minute,
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
