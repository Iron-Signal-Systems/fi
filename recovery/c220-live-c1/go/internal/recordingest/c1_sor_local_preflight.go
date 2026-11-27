//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "errors"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)

// C1SoRLocalCanonicalStatus never touches Pending or writes to canonical.
func C1SoRLocalCanonicalStatus(ctx context.Context,c C1SoRLocalConfig,
    generation,receipt string)(c1handoff.FinalStatus,error){
    if err:=validateC1SoRLocalConfig(c);err!=nil{return c1handoff.FinalNone,err}
    if generation==""||receipt==""{return c1handoff.FinalNone,errors.New("FI C1 local: exact original receipt required")}
    return c1ReadCanonicalAcceptanceAfterB(ctx,c.WorkerDSN,c.SourceID,generation,receipt)
}

// No RAM mount, TLS, fi-ingest jail or network service is needed for local
// fi-sor startup. This check is read-only and never creates a stage directory.
func PreflightC1SoRLocal(ctx context.Context,c C1SoRLocalConfig)error{
    if ctx==nil{return errors.New("FI C1 local: missing context")}
    if err:=validateC1SoRLocalConfig(c);err!=nil{return err}
    conn,_,err:=openC1SoRLocalSQL(ctx,c.WorkerDSN,"")
    if err!=nil{return err}
    defer conn.Close(context.Background())
    // Existing fail-closed governed Pending grants and schema preflight.
    if c.Custody.BenchmarkClone{return c1PreflightLocalGovernedPendingSQL(ctx,c.WorkerDSN)}
    if err:=c1PreflightDirectCanonicalSQL(ctx,c.WorkerDSN);err!=nil{return err}
    return c1PreflightLocalPublisher(ctx,c.PublisherDSN)
}
