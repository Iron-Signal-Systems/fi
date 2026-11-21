//go:build freebsd && fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Explicit one-shot OFFLINE FI C1 private SQL schema installation.
// It never runs from rc.conf, fi-ingest, receiver, the fi-sor normal
// service or an ordinary full-generation ingest command.
package main

import (
    "context"
    "errors"
    "flag"
    "fmt"
    "os"
    "os/signal"
    "strings"
    "syscall"

    "github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
    "github.com/jackc/pgx/v5"
)

func run(ctx context.Context)error{
    flags:=flag.NewFlagSet("fi-c1-private-schema",flag.ContinueOnError)
    dsn:=flags.String("postgres-admin-local","",
        "privileged local Unix-domain PostgreSQL18 DSN (use PGPASSFILE, not password in args)")
    if err:=flags.Parse(os.Args[1:]);err!=nil{return err}
    if flags.NArg()!=0||*dsn==""{
        return errors.New("FI C1 schema: one explicit local PostgreSQL admin DSN required")
    }
    if os.Getenv("FI_C1_SCHEMA_INSTALL_APPROVED")!="OFFLINE_PRIVATE_STAGE_ONLY"{
        return errors.New("FI C1 schema: explicit OFFLINE_PRIVATE_STAGE_ONLY operator authorization missing")
    }
    if strings.Contains(*dsn,"password=")||strings.Contains(*dsn,"://"){
        return errors.New("FI C1 schema: credentials and URI DSNs forbidden on command line; use PGPASSFILE")
    }
    cfg,err:=pgx.ParseConfig(*dsn)
    if err!=nil{return err}
    if !strings.HasPrefix(cfg.Host,"/")||cfg.Database!="fi"{
        return errors.New("FI C1 schema: UNIX socket and exact FI local database required")
    }
    conn,err:=pgx.ConnectConfig(ctx,cfg)
    if err!=nil{return err}
    defer conn.Close(context.Background())
    return recordingest.InstallC1PrivateSchemas(ctx,conn)
}

func main(){
    ctx,stop:=signal.NotifyContext(context.Background(),syscall.SIGINT,syscall.SIGTERM)
    defer stop()
    if err:=run(ctx);err!=nil{
        fmt.Fprintln(os.Stderr,"FI C1 PRIVATE SCHEMA INSTALL BLOCKED:",err)
        os.Exit(1)
    }
}
