//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 C220 private 8GiB SourceParent diagnostic only. No SQL/row/schema changes.
package recordingest

import (
    "context"
    "errors"
    "os"
    "time"

    "github.com/jackc/pgx/v5"
)

func privateC1SourceProfileMode()(bool,error) {
    v:=os.Getenv("FI_C1_SOURCE_PROFILE_8G")
    if v==""||v=="0"{return false,nil}
    if v!="1"{return false,errors.New("FI C1: invalid SourceParent profiler selection")}
    if !privateC1Enabled()||
        os.Getenv("FI_C1_DEV_PREFIX8")!="1"||
        os.Getenv("FI_C1_SECURITY_8G_EXPERIMENT")!="1"||
        os.Getenv("FI_W512_C1_FULL_BACKLOG")=="1" {
        return false,errors.New("FI C1: SourceParent profiler is limited to the two-group optimized 8GiB private clone")
    }
    return true,nil
}

type privateC1SourceCopyTiming struct{
    CopyWall time.Duration
    NextWall time.Duration
    ValuesWall time.Duration
    Calls int64
    NextCalls int64
    ValuesCalls int64
}
func (p privateC1SourceCopyTiming) Remainder()time.Duration {
    d:=p.CopyWall-p.NextWall-p.ValuesWall
    if d<0{return 0}
    return d
}

// The adapter delegates to the existing P6 cursor. It measures only
// Next/Values time: pgx encode, socket transfer, server execution and waits
// remain in Remainder, which must NOT be called "server-only time".
type privateC1TimedSourceCursor struct{
    pgx.CopyFromSource
    timing *privateC1SourceCopyTiming
}
func(c *privateC1TimedSourceCursor) Next()bool{
    started:=time.Now()
    ok:=c.CopyFromSource.Next()
    c.timing.NextWall+=time.Since(started)
    c.timing.NextCalls++
    return ok
}
func(c *privateC1TimedSourceCursor) Values()([]any,error){
    started:=time.Now()
    values,err:=c.CopyFromSource.Values()
    c.timing.ValuesWall+=time.Since(started)
    c.timing.ValuesCalls++
    return values,err
}

// This wraps only the ordered parent transaction, *beneath* the existing
// privateProjectionTx SQL schema rewrite. It adds no extra SQL connection.
type privateC1TimedSourceTx struct{
    pgx.Tx
    timing *privateC1SourceCopyTiming
}
func(t *privateC1TimedSourceTx) CopyFrom(ctx context.Context,table pgx.Identifier,
    columns []string,source pgx.CopyFromSource)(int64,error){
    if t==nil||t.Tx==nil||t.timing==nil||
        len(table)!=2||table[0]!=privateProjectionSchema||table[1]!="source_record"{
        return 0,errors.New("FI C1: SourceParent profiler requires only the shadow source_record COPY")
    }
    wrapped:=&privateC1TimedSourceCursor{CopyFromSource:source,timing:t.timing}
    started:=time.Now()
    n,err:=t.Tx.CopyFrom(ctx,table,columns,wrapped)
    t.timing.CopyWall+=time.Since(started)
    t.timing.Calls++
    return n,err
}
