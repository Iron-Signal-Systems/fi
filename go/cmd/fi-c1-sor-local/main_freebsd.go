//go:build freebsd && fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// One-jail C1. Nothing uses fi-ingest, an inter-jail socket, or host RAM.
// This executable also hosts its own independent B child OS process.
package main

import (
    "context"
    "errors"
    "flag"
    "fmt"
    "os"
    "os/signal"
    "path/filepath"
    "syscall"
    "time"
    "strings"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

func main() {
    if len(os.Args)==2&&os.Args[1]=="--c1-b-child"{
        if os.Geteuid()==0{fatal(errors.New("FI C1 B: refuse root execution"))}
        ctx,stop:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM)
        defer stop()
        if err:=recordingest.RunC1SoRNativeBChild(ctx,os.Stdin,os.Stdout);err!=nil{fatal(err)}
        return
    }
    f:=flag.NewFlagSet("fi-c1-sor-local",flag.ExitOnError)
    source:=f.String("source-id","","one original sender: explicit generation or single-source READY")
    sources:=f.String("sources","","ordered, comma-separated registered senders for one sequential READY processor")
    gen:=f.String("generation-id","","one original signed generation")
    ready:=f.String("ready-root","","original receiver READY queue (single finite pass)")
    batch:=f.Uint64("ready-batch-size",16,"max READY markers per pass")
    continuous:=f.Bool("continuous",false,"run governed READY passes until interrupted; disabled by default")
    poll:=f.Duration("poll-interval",5*time.Second,"interval between finite READY passes; only with continuous")
    custody:=f.String("custody-root","","receiver original generation custody mounted read-only in fi-sor")
    recorded:=f.String("recorded-root","","receiver original recorded receipts mounted read-only in fi-sor")
    namespaces:=f.Bool("source-namespaces",false,"original per-source receipt namespaces")
    db:=f.String("postgres-local","","fi-sor local Unix socket DSN, fi_ingest")
    publisher:=f.String("postgres-publisher-local","","fi-sor local canonical publisher Unix socket DSN")
    max:=f.Int("sql-workers-max",32,"tested adaptive shared SQL pool maximum")
    replay:=f.Bool("reconcile-private-replay",false,"EXPLICIT recovery only, requires intact original custody + read-only PostgreSQL audit")
    staging:=f.String("staging-root","","disposable local fast-pool scratch for receiver-verified batch extraction; never receiver custody")
    preflight:=f.Bool("preflight",false,"read-only: verify local mode, custody mounts and DB without staging or ingestion")
    cloneRoot:=f.String("benchmark-clone-root","","explicit isolated C220 benchmark PGDATA root; enforces physical worker/publisher cluster identity")
    cloneSystemID:=f.String("benchmark-system-id","","independent postgres-administrator-verified unique clone system identifier")
    canonical:=f.Uint64("max-canonical-bytes",75161927680,"receiver canonical limit")
    encoded:=f.Uint64("max-encoded-bytes",68719476736,"receiver encoded limit")
    manifest:=f.Uint64("max-manifest-bytes",1048576,"original manifest byte limit")
    if err:=f.Parse(os.Args[1:]);err!=nil{fatal(err)}
    if f.NArg()!=0{fatal(errors.New("FI C1 local: positional arguments forbidden"))}
    if os.Geteuid()==0{fatal(errors.New("FI C1 local: refuse root; run as fi-sor service account"))}
    if (*gen=="")==(*ready=="")||*staging==""||
       *custody==""||*recorded==""||*db==""||*publisher==""{
        fatal(errors.New("FI C1 local: one generation OR READY queue, signed custody and both local SQL roles required"))
    }
    if (*source=="")==(*sources==""){
        fatal(errors.New("FI C1 local: choose one source-id OR a multi-source READY roster"))
    }
    if *sources!="" && *ready==""{
        fatal(errors.New("FI C1 local: multi-source mode requires original READY queue"))
    }
    orderedSources:=make([]string,0,2)
    if *source!=""{
        orderedSources=append(orderedSources,*source)
    }else{
        seen:=make(map[string]bool)
        for _,name:=range strings.Split(*sources,","){
            name=strings.TrimSpace(name)
            if name==""||seen[name]||strings.ContainsAny(name,"/\\"){
                fatal(errors.New("FI C1 local: invalid or duplicate READY source identity"))
            }
            seen[name]=true
            orderedSources=append(orderedSources,name)
        }
    }
    if *ready!="" && *batch==0{fatal(errors.New("FI C1 local: READY pass must be bounded"))}
    if *continuous && (*ready==""||*poll<=0){
        fatal(errors.New("FI C1 local: continuous mode requires READY and a positive poll interval"))
    }
    if *replay && *ready!=""{
        fatal(errors.New("FI C1 local: automatic READY ingestion cannot enable Pending replay"))
    }
    if *cloneRoot!="" && (*ready!=""||*gen==""||*continuous||*replay||*cloneSystemID==""){
        fatal(errors.New("FI C1 benchmark: require one original generation, isolated system identifier, no READY, no continuous mode and no Pending replay"))
    }
    if *cloneRoot=="" && *cloneSystemID!=""{
        fatal(errors.New("FI C1 benchmark: PostgreSQL system identifier without physical clone path"))
    }
    if e:=c1handoff.RequireFreeBSDReadOnlyCustody(*custody);e!=nil{fatal(e)}
    if e:=c1handoff.RequireFreeBSDReadOnlyCustody(*recorded);e!=nil{fatal(e)}
    // The only writable source staging lives on fi-sor's local fast pool.
    // It is disposable, never a second receiver custody authority.
    stageInfo,e:=os.Lstat(*staging)
    if e!=nil||!stageInfo.IsDir()||stageInfo.Mode()&os.ModeSymlink!=0||
        !filepath.IsAbs(*staging){
        fatal(errors.New("FI C1 local: explicit existing non-symlink local staging directory required"))
    }
    config:=recordingest.C1SoRLocalConfig{
        SourceID:orderedSources[0],WorkerDSN:*db,PublisherDSN:*publisher,
        SQLWorkersMax:*max,AllowReplay:*replay,
        Custody:recordingest.C1NativeBCustodyConfig{
            CustodyRoot:*custody,RecordedRoot:*recorded,
            SourceNamespaces:*namespaces,MaxCanonicalBytes:*canonical,
            MaxEncodedBytes:*encoded,MaxManifestBytes:*manifest,
        },
    }
    ctx,stop:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM)
    defer stop()
    // Read-only physical PGDATA fence BEFORE signed generation loading and
    // BEFORE any Pending SQL admission or canonical publication.
    if *cloneRoot!=""{
        if e:=recordingest.PreflightC1SoRBenchmarkClone(ctx,config,*cloneRoot,*cloneSystemID);e!=nil{fatal(e)}
    }
    if *preflight{
        if e:=recordingest.PreflightC1SoRLocal(ctx,config);e!=nil{fatal(e)}
        if *gen!=""{
            if _,e:=recordingest.C1SoRLocalRecordedReceipt(config,*gen);e!=nil{fatal(e)}
        }
        fmt.Println("FI C1 SOR SINGLE-JAIL READ-ONLY PREFLIGHT PASS fi_ingest_jail_unused=true signed_receiver_custody_readonly=true postgres_local=true services_started=false")
        return
    }
    // Generation extraction is confined to this explicit fast-pool scratch.
    // This modifies no original receiver custody or canonical PostgreSQL.
    if e=os.Setenv("TMPDIR",*staging);e!=nil{fatal(e)}
    if *ready!=""{
        for {
            for _,originalSource:=range orderedSources{
                config.SourceID=originalSource
                accepted,e:=recordingest.RunC1SoRLocalReadyPass(ctx,config,*ready,*batch)
                if e!=nil{fatal(e)}
                fmt.Printf("FI C1 SOR LOCAL READY PASS source=%s accepted=%d original_custody_preserved=true continuous=%t\n",
                    originalSource,accepted,*continuous)
            }
            if !*continuous{return}
            timer:=time.NewTimer(*poll)
            select {
            case <-ctx.Done():
                timer.Stop()
                return
            case <-timer.C:
            }
        }
    }
    receipt,e:=recordingest.C1SoRLocalRecordedReceipt(config,*gen)
    if e!=nil{fatal(e)}
    status,e:=recordingest.C1SoRLocalCanonicalStatus(ctx,config,*gen,receipt)
    if e!=nil{fatal(e)}
    if status==c1handoff.FinalAccepted{
        fmt.Printf("FI C1 SOR LOCAL ALREADY ACCEPTED source=%s generation=%s no_replay=true\n",*source,*gen)
        return
    }
    totalStarted:=time.Now()
    signed,e:=recordingest.LoadRecordedGeneration(recordingest.C1SoRLocalGenerationLoad(config),*gen)
    if e!=nil{fatal(e)}
    extractionElapsed:=time.Since(totalStarted)
    result,runErr:=recordingest.RunC1SoRLocalGeneration(ctx,config,signed)
    closeErr:=signed.Close()
    totalElapsed:=time.Since(totalStarted)
    if e=errors.Join(runErr,closeErr);e!=nil{fatal(e)}
    if !result.CanonicalAccepted{fatal(errors.New("FI C1 local: canonical acceptance withheld"))}
    fmt.Printf("FI C1 SOR LOCAL COMPLETE source=%s generation=%s records=%d verify_extract_seconds=%.3f ingestion_seconds=%.3f ingestion_rec_s=%.2f full_wall_seconds=%.3f effective_rec_s=%.2f independently_verified=true canonical_accepted=true\n",
        result.SourceID,result.GenerationID,result.Records,
        extractionElapsed.Seconds(),result.IngestElapsed.Seconds(),result.IngestRecordsPerSecond,
        totalElapsed.Seconds(),float64(result.Records)/totalElapsed.Seconds())
}
func fatal(err error){fmt.Fprintln(os.Stderr,"FI C1 SOR LOCAL STOP:",err);os.Exit(1)}
