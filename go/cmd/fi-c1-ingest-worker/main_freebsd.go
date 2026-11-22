//go:build freebsd && fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// This replaces the FI ingest PROCESSING executable after C1 acceptance.
// It is built as /usr/local/sbin/fi-ingest-worker in the fi-ingest jail.
// There is no PostgreSQL client or SQL writer in this process.
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
    flags:=flag.NewFlagSet("fi-ingest-worker-c1",flag.ExitOnError)
    source:=flags.String("source-id","","enabled signed receiver source identity")
    generation:=flags.String("generation-id","","original signed generation identity")
    custody:=flags.String("custody-root","","read-only receiver generation custody")
    recorded:=flags.String("recorded-root","","read-only durable recorded-receipt custody")
    ns:=flags.Bool("source-namespaces",false,"use installed per-source recorded custody namespaces")
    target:=flags.String("sor-address","","private fi-sor C1 mTLS control and COMMIT ACK listener")
    ram:=flags.String("shared-ram-dir","","fi-ingest write view of host tmpfs C1 handoff")
    tlsCert:=flags.String("tls-cert","","fi-ingest mTLS client certificate")
    tlsKey:=flags.String("tls-key","","fi-ingest mTLS private key")
    tlsCA:=flags.String("tls-ca","","pinned C1 trust CA PEM")
    sorDNS:=flags.String("sor-server-dns","","exact fi-sor server certificate DNS SAN")
    startBatch:=flags.Int("start-batch",0,"original signed batch index after separately verified seed")
    canonical:=flags.Uint64("max-canonical-bytes",75161927680,"receiver generation canonical byte ceiling")
    encoded:=flags.Uint64("max-encoded-bytes",68719476736,"receiver generation encoded byte ceiling")
    manifest:=flags.Uint64("max-manifest-bytes",1048576,"receiver manifest byte ceiling")
    if err:=flags.Parse(os.Args[1:]);err!=nil{fatal(err)}
    if flags.NArg()!=0{fatal(errors.New("FI C1 ingest: no positional arguments allowed"))}
    if os.Geteuid()==0{fatal(errors.New("FI C1 ingest: refuse root execution"))}
    if *source==""||*generation==""||*custody==""||*recorded==""||*ram==""{
        fatal(errors.New("FI C1 ingest: signed source, generation, and both custody roots required"))
    }
    ramMount,e:=c1handoff.NewRAMStore(*ram)
    if e!=nil{fatal(e)}
    if e=c1handoff.RequireFreeBSDRAMMount(ramMount,false);e!=nil{fatal(e)}
    ctx,stop:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM)
    defer stop()
    signed,err:=recordingest.LoadRecordedGeneration(recordingest.GenerationLoadConfig{
        CustodyRoot:*custody,RecordedRoot:*recorded,SourceID:*source,
        SourceNamespaces:*ns,MaxCanonicalBytes:*canonical,
        MaxEncodedBytes:*encoded,MaxManifestBytes:*manifest,
    },*generation)
    if err!=nil{fatal(fmt.Errorf("FI C1 ingest: original receiver custody validation: %w",err))}
    defer signed.Close()
    result,err:=recordingest.RunC1IngestGeneration(ctx,signed,
        recordingest.C1IngestTransport{
            SoRAddress:*target,ExpectedSoRServerDNS:*sorDNS,StartBatch:*startBatch,
            SharedRAMDir:*ram,
            TLSIdentity:c1handoff.TLSFiles{Certificate:*tlsCert,
                PrivateKey:*tlsKey,TrustCA:*tlsCA},
        })
    if err!=nil{fatal(err)}
    fmt.Printf("FI C1 SQL AND INDEPENDENT B source=%s generation=%s records=%d batches=%d groups=%d independently_verified=%t canonical_accepted=%t\n",
        result.SourceID,result.GenerationID,result.NewRecords,
        result.SignedBatches,result.ReportingGroups,
        result.IndependentlyVerified,result.Published)
    if !result.IndependentlyVerified{
        fatal(errors.New("FI C1: signed generation lacks independent original-custody verifier B final proof"))
    }
    if !result.Published{
        fatal(errors.New("FI C1: independent B verified SQL stage, but canonical Accepted transaction is not yet integrated; receiver acknowledgment withheld"))
    }
    fmt.Printf("FI C1 CANONICAL ACCEPTED source=%s generation=%s records=%d\n",
        result.SourceID,result.GenerationID,result.NewRecords)
}
func fatal(err error){
    fmt.Fprintln(os.Stderr,"FI C1 INGEST STOP:",err)
    os.Exit(1)
}
