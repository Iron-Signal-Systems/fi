// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "errors"
    "testing"

    "github.com/jackc/pgx/v5"
)

type privateC1SourceProfileFakeTx struct{
    pgx.Tx
    table pgx.Identifier
    columns []string
    rows int64
}
func(t *privateC1SourceProfileFakeTx) CopyFrom(_ context.Context,table pgx.Identifier,
    cols []string,src pgx.CopyFromSource)(int64,error){
    t.table=append(pgx.Identifier(nil),table...)
    t.columns=append([]string(nil),cols...)
    for src.Next(){
        values,err:=src.Values()
        if err!=nil{return 0,err}
        if len(values)!=len(cols){return 0,errors.New("unexpected COPY column cardinality")}
        t.rows++
    }
    if err:=src.Err();err!=nil{return 0,err}
    return t.rows,nil
}
func TestPrivateC1SourceProfileCopiesSamePrivateRows(t *testing.T){
    fake:=&privateC1SourceProfileFakeTx{}
    timing:=&privateC1SourceCopyTiming{}
    tx:=privateProjectionTx{Tx:&privateC1TimedSourceTx{Tx:fake,timing:timing}}
    cols:=[]string{"one","two"}
    src:=pgx.CopyFromSlice(3,func(i int)([]any,error){return []any{i,int64(i+10)},nil})
    n,err:=tx.CopyFrom(context.Background(),pgx.Identifier{"fi","source_record"},cols,src)
    if err!=nil||n!=3||timing.Calls!=1||timing.ValuesCalls!=3||timing.NextCalls!=4{
        t.Fatalf("COPY proof: n=%d err=%v timing=%+v",n,err,*timing)
    }
    if len(fake.table)!=2||fake.table[0]!=privateProjectionSchema||fake.table[1]!="source_record"||
        len(fake.columns)!=len(cols)||timing.Remainder()<0 {
        t.Fatal("profiling changed shadow table/columns or produced negative remainder")
    }
    if _,err=tx.CopyFrom(context.Background(),pgx.Identifier{"fi","windows_security_event"},cols,pgx.CopyFromSlice(0,func(i int)([]any,error){return nil,nil}));err==nil{
        t.Fatal("SourceParent profiling accepted another table")
    }
}
func TestPrivateC1SourceProfileOptInOnlyForOptimizedEightGiB(t *testing.T){
    t.Setenv("FI_W512_C1_P6_DIRECT","1")
    t.Setenv("FI_W512_P6_FAMILY_SQL","1")
    t.Setenv("FI_C1_DEV_PREFIX8","1")
    t.Setenv("FI_C1_SECURITY_8G_EXPERIMENT","1")
    t.Setenv("FI_W512_C1_FULL_BACKLOG","0")
    t.Setenv("FI_C1_SOURCE_PROFILE_8G","1")
    if enabled,err:=privateC1SourceProfileMode();err!=nil||!enabled{t.Fatalf("expected private-only profiler: %v",err)}
    t.Setenv("FI_C1_DEV_PREFIX8","0")
    if _,err:=privateC1SourceProfileMode();err==nil{t.Fatal("profiler permitted outside 8GiB prefix")}
    t.Setenv("FI_C1_DEV_PREFIX8","1")
    t.Setenv("FI_C1_SECURITY_8G_EXPERIMENT","0")
    if _,err:=privateC1SourceProfileMode();err==nil{t.Fatal("profiler permitted outside candidate")}
    t.Setenv("FI_C1_SECURITY_8G_EXPERIMENT","1")
    t.Setenv("FI_W512_C1_FULL_BACKLOG","1")
    if _,err:=privateC1SourceProfileMode();err==nil{t.Fatal("profiler permitted on full backlog")}
    t.Setenv("FI_W512_C1_FULL_BACKLOG","0")
    t.Setenv("FI_C1_SOURCE_PROFILE_8G","invalid")
    if _,err:=privateC1SourceProfileMode();err==nil{t.Fatal("invalid profiler flag accepted")}
    t.Setenv("FI_C1_SOURCE_PROFILE_8G","0")
    if enabled,err:=privateC1SourceProfileMode();err!=nil||enabled{t.Fatal("profiler control should be off")}
}
