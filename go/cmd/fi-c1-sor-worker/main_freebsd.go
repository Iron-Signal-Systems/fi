//go:build freebsd && fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1's PostgreSQL writer is a dedicated process INSIDE the fi-sor jail.
// It is never run from fi-ingest and never publishes a canonical generation.
package main

import (
    "context"
    "errors"
    "flag"
    "fmt"
    "os"
    "os/signal"
    "syscall"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

func main(){
    if len(os.Args)==2 && os.Args[1]=="--c1-b-child" {
        if os.Geteuid()==0{fatal(errors.New("FI C1 B: refuse root execution"))}
        ctx,stop:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM)
        defer stop()
        if err:=recordingest.RunC1SoRNativeBChild(ctx,os.Stdin,os.Stdout);err!=nil{fatal(err)}
        return
    }
    flags:=flag.NewFlagSet("fi-c1-sor-worker",flag.ExitOnError)
    bind:=flags.String("bind","","private fi-sor workload address for mTLS handoff")
    db:=flags.String("postgres-local","","PostgreSQL Unix-domain DSN inside fi-sor, dbname=fi user=fi_ingest")
    ram:=flags.String("shared-ram-dir","","fi-sor read-only nullfs view of C1 host tmpfs")
    max:=flags.Int("sql-workers-max",32,"bounded native C1 shared PostgreSQL workers (1..32)")
    cert:=flags.String("tls-cert","","fi-sor dedicated mTLS server certificate")
    key:=flags.String("tls-key","","fi-sor dedicated mTLS private key")
    ca:=flags.String("tls-ca","","pinned internal C1 CA trust PEM")
    ingest:=flags.String("ingest-client-dns","","exact DNS SAN of fi-ingest mTLS client")
    if err:=flags.Parse(os.Args[1:]);err!=nil{fatal(err)}
    if flags.NArg()!=0 {fatal(errors.New("FI C1 SoR: no positional arguments allowed"))}
    if os.Geteuid()==0 {fatal(errors.New("FI C1 SoR: refuse root execution; dedicate an unprivileged fi-sor service account"))}
    if *ram==""{fatal(errors.New("FI C1 SoR: shared RAM mount required for two-jail C1 service"))}
    ramMount,e:=c1handoff.NewRAMStore(*ram)
    if e!=nil{fatal(e)}
    if e=c1handoff.RequireFreeBSDRAMMount(ramMount,true);e!=nil{fatal(e)}
    cfg:=recordingest.C1SoRServerConfig{
        Bind:*bind,LocalPostgresDSN:*db,SQLWorkersMax:*max,
        SharedRAMDir:*ram,
        ExpectedIngestClientDNS:*ingest,
        TransportCert:c1handoff.TLSFiles{
            Certificate:*cert,PrivateKey:*key,TrustCA:*ca,
        },
    }
    ctx,stop:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM)
    defer stop()
    if err:=recordingest.RunC1SoRWorker(ctx,cfg);err!=nil{
        fatal(err)
    }
}
func fatal(err error){
    fmt.Fprintln(os.Stderr,"FI C1 SOR STOP:",err)
    os.Exit(1)
}
