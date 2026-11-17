// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// P10 ISOLATED C220 CLONE: P6 native source/relational SQL, six real backend
// connections (ordered source parent plus five independent child writers).
// No new pending_source_record staging, no P7 preparer bridge, no alternate
// relational projectors. Failure renders this disposable SQL clone unusable;
// never resume it or treat partially committed parents as a checkpoint.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "os"
    "strings"
    "sync"
    "time"

    "github.com/jackc/pgx/v5"
)

type privateP10SQLJob struct {
    rows []privateP6Record
    done chan error
}
type privateP10SQLLane struct {
    family privateP6Family
    conn *pgx.Conn
    jobs chan privateP10SQLJob
    outstanding []chan error // owner: canonical reader goroutine only
    committed int64
    handoffs int64
    err error
}
type privateP10FiveSQL struct {
    parent *pgx.Conn
    lanes [privateP6FamilyCount]*privateP10SQLLane
    sourceID string
    ctx context.Context
    cancel context.CancelFunc
    wg sync.WaitGroup
    parentRows int64
    parentHandoffs int64
    closed bool
    failed error
}

func privateP10Enabled() bool {
    return os.Getenv("FI_W512_P10_P6_DIRECT")=="1" &&
        os.Getenv("FI_W512_P7_SQL_WRITERS")=="" &&
        os.Getenv("FI_W512_P8_REUSE")=="" &&
        os.Getenv("FI_W512_P9_DIRECT_STREAM")=="" &&
        privateP6Selected()
}

func privateP10CloneConnection(ctx context.Context,dsn,expectedPGDATA string)(*pgx.Conn,int64,error){
    if dsn==""||expectedPGDATA==""||
        !strings.HasPrefix(expectedPGDATA,"/home/jwood/fi-window-bench-w512-family-p3-")||
        !strings.HasSuffix(expectedPGDATA,"/clone-w512-2g/data") ||
        !strings.Contains(dsn,"sslmode=disable")||
        !strings.Contains(dsn,"user=fi_ingest") ||
        !strings.Contains(dsn,"host=/var/tmp/fi-window-chunks-family-p3-") {
        return nil,0,errors.New("FI P10: exact private C220 clone DSN/PGDATA required")
    }
    conn,err:=pgx.Connect(ctx,dsn)
    if err!=nil{return nil,0,err}
    var path,user string
    var recovery bool
    var pid int64
    err=conn.QueryRow(ctx,`SELECT current_setting('data_directory'), current_user,
pg_is_in_recovery(),pg_backend_pid()::bigint`).Scan(&path,&user,&recovery,&pid)
    if err!=nil||path!=expectedPGDATA||user!="fi_ingest"||recovery||pid<=0{
        conn.Close(context.Background())
        return nil,0,fmt.Errorf("FI P10: backend must be private fi_ingest exact clone: pgdata=%q role=%q standby=%v pid=%d err=%v",path,user,recovery,pid,err)
    }
    return conn,pid,nil
}

func newPrivateP10FiveSQL(ctx context.Context,dsn,pgdata,sourceID string)(*privateP10FiveSQL,error){
    if !privateP10Enabled()||ctx==nil||sourceID==""{
        return nil,errors.New("FI P10: private P6 five-writer feature not selected")
    }
    owner,cancel:=context.WithCancel(ctx)
    w:=&privateP10FiveSQL{ctx:owner,cancel:cancel,sourceID:sourceID}
    cleanup:=func(){
        cancel()
        if w.parent!=nil { _=w.parent.Close(context.Background()) }
        for _,lane:=range w.lanes {
            if lane!=nil&&lane.conn!=nil {_=lane.conn.Close(context.Background())}
        }
    }
    parent,parentPID,err:=privateP10CloneConnection(ctx,dsn,pgdata)
    if err!=nil{cleanup();return nil,err}
    w.parent=parent
    pids:=map[int64]bool{parentPID:true}
    for i:=range w.lanes{
        conn,pid,e:=privateP10CloneConnection(ctx,dsn,pgdata)
        if e!=nil{cleanup();return nil,e}
        if pids[pid]{
            conn.Close(context.Background());cleanup()
            return nil,errors.New("FI P10: duplicate backend PID, five independent connections required")
        }
        pids[pid]=true
        w.lanes[i]=&privateP10SQLLane{family:privateP6Family(i),
            conn:conn,jobs:make(chan privateP10SQLJob,2)}
    }
    // Only after every connection is verified do SQL goroutines begin.
    for _,lane:=range w.lanes{
        w.wg.Add(1)
        go w.runLane(lane)
    }
    fmt.Printf("FI P10 P6 NATIVE SQL BACKENDS parent=1 family_writers=5 distinct_pids=%d clone_only=true\n",len(pids))
    return w,nil
}

func(w *privateP10FiveSQL) runLane(lane *privateP10SQLLane){
    defer w.wg.Done()
    for job:=range lane.jobs {
        err:=w.writeFamily(w.ctx,lane,job.rows)
        if err==nil{
            lane.committed+=int64(len(job.rows))
            lane.handoffs++
        }else{
            lane.err=err
        }
        job.done<-err
        close(job.done)
        // After failure, each later job gets the SAME error. This leaves
        // every completion channel signaled and avoids blocked Finish.
    }
}

func(w *privateP10FiveSQL) writeFamily(ctx context.Context,lane *privateP10SQLLane,rows []privateP6Record)error{
    if lane.err!=nil{return lane.err}
    if err:=ctx.Err();err!=nil{return err}
    tx,err:=lane.conn.Begin(ctx)
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    profile:=&ingestStageProfile{}
    coordinator,err:=newPrivateP6SQLCoordinator(privateProjectionTx{Tx:tx},
        w.sourceID,profile)
    if err!=nil{return err}
    writeCtx:=ctx
    if lane.family==privateP6File {
        writeCtx=context.WithValue(ctx,ntfsStageTimingContextKey{},&ntfsStageTimingCounters{})
    }
    if err=coordinator.Family(writeCtx,lane.family,rows);err!=nil{return err}
    return tx.Commit(ctx)
}

func(w *privateP10FiveSQL) Source(ctx context.Context,rows []privateP6Record)error{
    if w==nil||w.closed||len(rows)==0{return errors.New("FI P10: invalid source parent handoff")}
    if w.failed!=nil{return w.failed}
    tx,err:=w.parent.Begin(ctx)
    if err!=nil{w.failed=err;return err}
    defer tx.Rollback(context.Background())
    coordinator,err:=newPrivateP6SQLCoordinator(privateProjectionTx{Tx:tx},
        w.sourceID,&ingestStageProfile{})
    if err==nil{err=coordinator.Source(ctx,rows)}
    if err==nil{err=tx.Commit(ctx)}
    if err!=nil{
        w.failed=fmt.Errorf("FI P10: ordered P6 source parent failed: %w",err)
        return w.failed
    }
    w.parentRows+=int64(len(rows))
    w.parentHandoffs++
    return nil
}

func(w *privateP10FiveSQL) Family(ctx context.Context,f privateP6Family,rows []privateP6Record)error{
    if w==nil||w.closed||f>=privateP6FamilyCount||len(rows)==0{
        return errors.New("FI P10: invalid P6 family handoff")
    }
    if w.failed!=nil{return w.failed}
    lane:=w.lanes[f]
    if lane.err!=nil{
        w.failed=lane.err
        return w.failed
    }
    // At most 4 pending handed-off buffers per family; each is itself
    // bounded by the original P6 row/byte capacity. Do not grow an
    // unlimited backlog waiting for a slow SQL family.
    if len(lane.outstanding)>=4 {
        if err:=w.WaitFamily(ctx,f);err!=nil{return err}
    }
    job:=privateP10SQLJob{rows:rows,done:make(chan error,1)}
    select{
    case <-ctx.Done():return ctx.Err()
    case <-w.ctx.Done():return w.ctx.Err()
    case lane.jobs<-job:
    }
    lane.outstanding=append(lane.outstanding,job.done)
    return nil
}

func(w *privateP10FiveSQL) WaitFamily(ctx context.Context,f privateP6Family)error{
    if w==nil||f>=privateP6FamilyCount{return errors.New("FI P10: invalid SQL family barrier")}
    lane:=w.lanes[f]
    pending:=lane.outstanding
    lane.outstanding=nil
    for _,ack:=range pending {
        select{
        case <-ctx.Done():return ctx.Err()
        case err:=<-ack:
            if err!=nil{
                w.failed=fmt.Errorf("FI P10: family %s SQL commit: %w",privateP6FamilyNames[f],err)
                return w.failed
            }
        }
    }
    return nil
}
func(w *privateP10FiveSQL) WaitAll(ctx context.Context)error{
    if w==nil{return errors.New("FI P10: missing five SQL lanes")}
    var joined error
    // All 5 can run concurrently; wait only after all family buffers
    // have handed off their final batches.
    for f:=privateP6Family(0);f<privateP6FamilyCount;f++{
        joined=errors.Join(joined,w.WaitFamily(ctx,f))
    }
    if joined!=nil{return joined}
    var total int64
    for _,lane:=range w.lanes{total+=lane.committed}
    if total!=w.parentRows {
        return fmt.Errorf("FI P10: five committed child counts %d differ from P6 signed parent count %d",total,w.parentRows)
    }
    return nil
}
func(w *privateP10FiveSQL) Stats()(int64,int64,[privateP6FamilyCount]int64){
    var family [privateP6FamilyCount]int64
    if w==nil{return 0,0,family}
    var total int64
    for i,lane:=range w.lanes{
        family[i]=lane.committed
        total+=family[i]
    }
    return w.parentRows,total,family
}
func(w *privateP10FiveSQL) Close(){
    if w==nil||w.closed{return}
    w.closed=true
    for _,lane:=range w.lanes {
        if lane!=nil {close(lane.jobs)}
    }
    w.wg.Wait()
    w.cancel()
    for _,lane:=range w.lanes{
        if lane!=nil&&lane.conn!=nil {_=lane.conn.Close(context.Background())}
    }
    if w.parent!=nil {_=w.parent.Close(context.Background())}
}
var _ privateP6SQLHandoff=(*privateP10FiveSQL)(nil)
var _=time.Second
