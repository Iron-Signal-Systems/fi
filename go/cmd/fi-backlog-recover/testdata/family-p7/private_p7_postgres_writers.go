// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Five ACTUAL PostgreSQL relational family connections, plus one separate,
// synchronous source-parent ledger connection. All writes target only the
// private shadow schema. The completed window marker is written separately
// after five-lane SQL proof; this module MUST NOT be used on the live SoR.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "strings"
    "sync"
    "time"

    "github.com/jackc/pgx/v5"
)

type privateP7PGSource struct{
    conn *pgx.Conn
    sourceID string
    mu sync.Mutex
    lastBatch int
    lastOrdinal int64
    copied int64
    copyCalls int64
}
type privateP7PGFamily struct{
    conn *pgx.Conn
    family privateP6Family
    sourceID string
    fieldPartition string
    baseContext context.Context
    profile ingestStageProfile
    totalRecords int64
    totalHandoffs int64
    totalElapsed time.Duration
}

func privateP7FiveWriterSelected()bool{
    return os.Getenv("FI_W512_P7_SQL_WRITERS")=="5" &&
        os.Getenv("FI_W512_P6_FAMILY_SQL")=="1" &&
        os.Getenv("FI_W512_P5_PERSISTENT")=="1"
}
// Verify EVERY connection, including the control/marker connection,
// against an exact caller-pinned private clone data directory. Matching
// role/database alone is unsafe because authoritative FI uses fi_ingest/fi.
func privateP7VerifyCloneConnection(ctx context.Context,conn *pgx.Conn,
    expectedDataDir string)(int32,error){
    if !privateP7FiveWriterSelected()||ctx==nil||conn==nil||
        expectedDataDir=="" || !filepath.IsAbs(expectedDataDir) ||
        (!strings.Contains(expectedDataDir,"fi-window-bench-w512-") &&
         !strings.Contains(expectedDataDir,"fi-w512-family-clone-")){
        return 0,errors.New("FI five-writer: clone SQL identity/gates missing")
    }
    var who,db string
    var inRecovery bool
    var pid int32
    var actualDataDir string
    var fsyncOn,commitOn,fullPageOn bool
    err:=conn.QueryRow(ctx,`SELECT current_user,current_database(),
        pg_is_in_recovery(),pg_backend_pid(),current_setting('data_directory'),
        current_setting('fsync')='on',
        current_setting('synchronous_commit')='on',
        current_setting('full_page_writes')='on'`).
        Scan(&who,&db,&inRecovery,&pid,&actualDataDir,
            &fsyncOn,&commitOn,&fullPageOn)
    if err!=nil||who!="fi_ingest"||db!="fi"||inRecovery||pid<=0||
        filepath.Clean(actualDataDir)!=filepath.Clean(expectedDataDir)||
        !fsyncOn||!commitOn||!fullPageOn{
        return 0,fmt.Errorf("FI five-writer: non-clone PostgreSQL target or weak durability role=%q db=%q data=%q expected=%q replica=%t fsync=%t commit=%t fullpage=%t pid=%d: %v",
            who,db,actualDataDir,expectedDataDir,inRecovery,fsyncOn,commitOn,fullPageOn,pid,err)
    }
    return pid,nil
}
func privateP7ConnectVerified(ctx context.Context,dsn,expectedDataDir string)(*pgx.Conn,int32,error){
    if ctx==nil||dsn==""{return nil,0,errors.New("FI P7: SQL DSN missing")}
    conn,err:=pgx.Connect(ctx,dsn)
    if err!=nil{return nil,0,fmt.Errorf("FI five-writer: clone connection: %w",err)}
    pid,err:=privateP7VerifyCloneConnection(ctx,conn,expectedDataDir)
    if err!=nil{_ = conn.Close(ctx);return nil,0,err}
    return conn,pid,nil
}

func(s *privateP7PGSource) Source(ctx context.Context,rows []privateP6Record)error{
    if s==nil||s.conn==nil||ctx==nil||len(rows)==0{
        return errors.New("FI P7 source parent: invalid ledger request")
    }
    s.mu.Lock()
    defer s.mu.Unlock()
    for i,r:=range rows{
        if !r.valid() || r.signedBatchIndex<s.lastBatch ||
            (r.signedBatchIndex==s.lastBatch && r.ordinal<=s.lastOrdinal){
            return fmt.Errorf("FI P7 source parent: signed order changed at %d",i)
        }
        s.lastBatch,s.lastOrdinal=r.signedBatchIndex,r.ordinal
    }
    tx,err:=s.conn.Begin(ctx)
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    var profile ingestStageProfile
    writer,err:=newPrivateP6SQLCoordinator(
        privateProjectionTx{Tx:tx},s.sourceID,&profile)
    if err!=nil{return err}
    if err=writer.Source(ctx,rows);err!=nil{return err}
    if err=tx.Commit(ctx);err!=nil{return err}
    s.copied+=int64(len(rows))
    s.copyCalls++
    return nil
}
func(s *privateP7PGSource)Close(ctx context.Context)error{
    if s==nil||s.conn==nil{return nil}
    return s.conn.Close(ctx)
}

func(w *privateP7PGFamily) Write(ctx context.Context,rows []privateP6Record)error{
    if w==nil||w.conn==nil||ctx==nil||len(rows)==0{
        return errors.New("FI P7 family: invalid PostgreSQL typed handoff")
    }
    started:=time.Now()
    tx,err:=w.conn.Begin(ctx)
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    shadow:=privateProjectionTx{Tx:tx,fieldPartition:w.fieldPartition}
    writer:=&privateP6SQLCoordinator{tx:shadow,sourceID:w.sourceID,profile:&w.profile}
    // Private scope: no concurrent family may share mutable NTFS caches,
    // hash/ACE COPY streams, USN change buffers or their transaction.
    projectCtx:=context.WithValue(w.baseContext,ntfsObjectCacheContextKey{},newNTFSObjectCache())
    projectCtx=context.WithValue(projectCtx,ntfsScopeIdentityCacheContextKey{},newNTFSScopeIdentityCache())
    hashCopy:=newContentHashCopyState()
    aceCopy:=newACECopyState()
    usnCopy:=newUSNChangeCopyState()
    projectCtx=context.WithValue(projectCtx,contentHashCopyContextKey{},hashCopy)
    projectCtx=context.WithValue(projectCtx,aceCopyContextKey{},aceCopy)
    projectCtx=context.WithValue(projectCtx,usnChangeCopyContextKey{},usnCopy)
    // Value-bearing scoped context MUST carry the caller's exact signed
    // generation, scope and USN capture state. It is never synthesized here.
    if _,ok:=projectCtx.Value(ntfsStageTimingContextKey{}).(*ntfsStageTimingCounters);!ok{
        return errors.New("FI P7 family: original NTFS validation counters absent")
    }
    if w.family==privateP6USN {
        if projectCtx.Value(usnCaptureContextKey{})==nil {
            return errors.New("FI P7 USN: signed capture state missing")
        }
    }
    if err:=writer.Family(projectCtx,w.family,rows);err!=nil{return err}
    if err:=usnCopy.flushAll(projectCtx,shadow);err!=nil{
        return fmt.Errorf("FI P7 USN child COPY: %w",err)
    }
    if err:=hashCopy.flush(projectCtx,shadow);err!=nil{
        return fmt.Errorf("FI P7 content hashes: %w",err)
    }
    if err:=aceCopy.flushAll(projectCtx,shadow);err!=nil{
        return fmt.Errorf("FI P7 security ACE children: %w",err)
    }
    if err:=tx.Commit(ctx);err!=nil{return err}
    w.totalRecords+=int64(len(rows))
    w.totalHandoffs++
    w.totalElapsed+=time.Since(started)
    return nil
}
func(w *privateP7PGFamily) Close(ctx context.Context)error{
    if w==nil||w.conn==nil{return nil}
    return w.conn.Close(ctx)
}

// There are five separate typed PostgreSQL backends plus ONE synchronous
// parent-ledger connection (six total). Backend PID uniqueness is verified;
// the coordinator is not secretly multiplexing the five family SQL writers.
func newPrivateP7PostgresFiveWriter(ctx context.Context,dsn,sourceID,
    fieldPartition,expectedDataDir string)(*privateP7FiveWriter,error){
    if sourceID==""||!privateP7FiveWriterSelected(){
        return nil,errors.New("FI P7: source ID or five-connection feature gate missing")
    }
    ledgerConn,ledgerPID,err:=privateP7ConnectVerified(ctx,dsn,expectedDataDir)
    if err!=nil{return nil,err}
    ledger:=&privateP7PGSource{conn:ledgerConn,sourceID:sourceID,lastBatch:-1}
    var mu sync.Mutex
    seen:=map[int32]bool{ledgerPID:true}
    factory:=func(ctx context.Context,f privateP6Family)(
        privateP7FamilyWriter,error,
    ){
        c,pid,err:=privateP7ConnectVerified(ctx,dsn,expectedDataDir)
        if err!=nil{return nil,err}
        mu.Lock()
        duplicate:=seen[pid]
        if !duplicate{seen[pid]=true}
        mu.Unlock()
        if duplicate{
            _=c.Close(ctx)
            return nil,errors.New("FI P7: two SQL families share a PostgreSQL backend PID")
        }
        return &privateP7PGFamily{
            conn:c,family:f,sourceID:sourceID,fieldPartition:fieldPartition,
            baseContext:ctx,
        },nil
    }
    sink,err:=newPrivateP7FiveWriter(ctx,ledger,factory)
    if err!=nil{return nil,err}
    mu.Lock();got:=len(seen);mu.Unlock()
    if got!=6{
        _=sink.Close(context.Background())
        return nil,fmt.Errorf("FI P7: need 5 distinct typed backends plus parent ledger, got %d",got)
    }
    fmt.Printf("FI P7 FIVE SQL BACKENDS VERIFIED typed_writers=5 parent_ledger=1 unique_backend_pids=6 shadow_only=true\n")
    return sink,nil
}
