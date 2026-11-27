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
    preflight:=flags.Bool("preflight",false,"READ ONLY: validate real jail C1 startup without listener, B child, or SQL writes")
    bind:=flags.String("bind","","private fi-sor workload address for mTLS handoff")
    db:=flags.String("postgres-local","","fi-sor SQL worker local DSN, dbname=fi user=fi_ingest")
    publisherDB:=flags.String("postgres-publisher-local","","separate fi-sor-only Unix-domain canonical publisher DSN, user=fi_c1_publisher")
    ram:=flags.String("shared-ram-dir","","fi-sor read-only nullfs view of C1 host tmpfs")
    custodyRoot:=flags.String("custody-root","","fi-sor read-only view of original signed receiver generation custody")
    recordedRoot:=flags.String("recorded-root","","fi-sor read-only original recorded-receipt custody")
    namespaces:=flags.Bool("source-namespaces",false,"original per-source recorded custody layout")
    canonicalMax:=flags.Uint64("max-canonical-bytes",75161927680,"original signed canonical byte ceiling")
    encodedMax:=flags.Uint64("max-encoded-bytes",68719476736,"original signed encoded byte ceiling")
    manifestMax:=flags.Uint64("max-manifest-bytes",1048576,"original signed manifest byte ceiling")
    publish:=flags.Bool("publish-verified-private",false,"OFFLINE DEVELOPMENT ONLY: atomic canonical promotion after complete signed private verification")
    publishSource:=flags.String("publish-source-id","","original signed source for explicit offline canonical publication")
    publishGeneration:=flags.String("publish-generation-id","","original signed generation for explicit offline canonical publication")
    attempt:=flags.String("publish-attempt-id","","new distinct canonical Accepted journal attempt identity")
    max:=flags.Int("sql-workers-max",32,"bounded native C1 shared PostgreSQL workers (1..32)")
    recoverPrivate:=flags.Bool("reconcile-private-replay",false,"DEVELOPMENT ONLY: reconcile dirty private PostgreSQL before replay from signed custody")
    cert:=flags.String("tls-cert","","fi-sor dedicated mTLS server certificate")
    key:=flags.String("tls-key","","fi-sor dedicated mTLS private key")
    ca:=flags.String("tls-ca","","pinned internal C1 CA trust PEM")
    ingest:=flags.String("ingest-client-dns","","exact DNS SAN of fi-ingest mTLS client")
    if err:=flags.Parse(os.Args[1:]);err!=nil{fatal(err)}
    if flags.NArg()!=0 {fatal(errors.New("FI C1 SoR: no positional arguments allowed"))}
    if os.Geteuid()==0 {fatal(errors.New("FI C1 SoR: refuse root execution; dedicate an unprivileged fi-sor service account"))}
    if *custodyRoot==""||*recordedRoot==""{
        fatal(errors.New("FI C1 SoR: both independent original signed custody roots required"))
    }
    if e:=c1handoff.RequireFreeBSDReadOnlyCustody(*custodyRoot);e!=nil{fatal(e)}
    if e:=c1handoff.RequireFreeBSDReadOnlyCustody(*recordedRoot);e!=nil{fatal(e)}
    custodyCfg:=recordingest.C1NativeBCustodyConfig{
        CustodyRoot:*custodyRoot,RecordedRoot:*recordedRoot,
        SourceNamespaces:*namespaces,MaxCanonicalBytes:*canonicalMax,
        MaxEncodedBytes:*encodedMax,MaxManifestBytes:*manifestMax,
    }
    if *preflight && *publish{
        fatal(errors.New("FI C1 SoR: preflight cannot publish or modify canonical PostgreSQL"))
    }
    if *publish{
        if os.Getenv("FI_C1_CANONICAL_PUBLISH_APPROVED")!="I_HAVE_VERIFIED_ISOLATED_CLONE"{
            fatal(errors.New("FI C1 publication: explicit isolated clone acceptance authorization absent"))
        }
        if *publishSource==""||*publishGeneration==""||*attempt==""||
            *bind!=""||*recoverPrivate{
            fatal(errors.New("FI C1 publication: explicit signed source/generation/unique attempt required; no active handoff server"))
        }
        ctx,stop:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM)
        defer stop()
        result,err:=recordingest.PublishC1VerifiedPrivateGeneration(ctx,*db,
            custodyCfg,*publishSource,*publishGeneration,*attempt)
        if err!=nil{fatal(err)}
        fmt.Printf("FI C1 CANONICAL PROMOTION outcome=%s source=%s generation=%s committed=%d attempt=%s\\n",
            result.Outcome,result.SourceID,result.GenerationID,
            result.RecordsCommitted,result.AttemptID)
        return
    }
    if *publishSource!=""||*publishGeneration!=""||*attempt!=""{
        fatal(errors.New("FI C1: canonical publication flags forbidden in active two-jail service"))
    }
    if *ram==""{fatal(errors.New("FI C1 SoR: shared RAM mount required"))}
    ramMount,e:=c1handoff.NewRAMStore(*ram)
    if e!=nil{fatal(e)}
    if e=c1handoff.RequireFreeBSDRAMMount(ramMount,true);e!=nil{fatal(e)}
    cfg:=recordingest.C1SoRServerConfig{
        Bind:*bind,LocalPostgresDSN:*db,PublisherPostgresDSN:*publisherDB,
        SQLWorkersMax:*max,
        SharedRAMDir:*ram,AllowC1Replay:*recoverPrivate,
        CustodyRoot:*custodyRoot,RecordedRoot:*recordedRoot,
        CustodySourceNamespaces:*namespaces,
        MaxCanonicalBytes:*canonicalMax,MaxEncodedBytes:*encodedMax,
        MaxManifestBytes:*manifestMax,
        ExpectedIngestClientDNS:*ingest,
        TransportCert:c1handoff.TLSFiles{
            Certificate:*cert,PrivateKey:*key,TrustCA:*ca,
        },
    }
    ctx,stop:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM)
    defer stop()
    if *preflight{
        if err:=recordingest.PreflightC1SoRWorker(ctx,cfg);err!=nil{fatal(err)}
        fmt.Println("FI C1 SOR READ-ONLY PREFLIGHT PASS local_pg18_roles_verified=true original_custody_readonly=true shared_ram_readonly=true mTLS_validated=true listener_started=false")
        return
    }
    if err:=recordingest.RunC1SoRWorker(ctx,cfg);err!=nil{
        fatal(err)
    }
}
func fatal(err error){
    fmt.Fprintln(os.Stderr,"FI C1 SOR STOP:",err)
    os.Exit(1)
}
