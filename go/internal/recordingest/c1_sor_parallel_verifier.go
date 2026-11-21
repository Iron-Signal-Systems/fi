//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1's verifier B runs on an independent READ-ONLY PostgreSQL session in
// fi-sor. It receives a notification only after original group sealing AND
// all SourceParent/five-family SQL COMMIT counts reach signed totals.
// Neither group seals nor B proof requests flush a C1 family buffer.
package recordingest

import (
    "context"
    "encoding/hex"
    "errors"
    "fmt"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/jackc/pgx/v5"
)

type c1SoRGroup struct {
    firstBatch,endBatch int
    count,bytes int64
}

// Exactly the same intact-signed-batch 4GiB grouping as fi-ingest. This
// function never touches SQL and never resets the P5/P6 buffers.
func c1SoRGroupPlan(batches []PreparedBatch,start int)([]c1SoRGroup,error){
    if start<0||start>=len(batches){return nil,errors.New("C1 verifier: missing original signed group start")}
    groups:=make([]c1SoRGroup,0,1)
    current:=c1SoRGroup{firstBatch:start,endBatch:start}
    for i:=start;i<len(batches);i++{
        b:=batches[i]
        count:=int64(b.Manifest.RecordCount)
        size:=b.Manifest.DataBytes
        if count<=0||size<=0||size>c1IngestReportingGroupBytes {
            return nil,fmt.Errorf("C1 verifier: invalid original batch %d counts or bytes",i)
        }
        if current.count>0 && size>c1IngestReportingGroupBytes-current.bytes {
            groups=append(groups,current)
            current=c1SoRGroup{firstBatch:i,endBatch:i}
        }
        current.endBatch=i+1
        current.count+=count
        current.bytes+=size
    }
    groups=append(groups,current)
    return groups,nil
}
func c1SoRCommitTracker(groups []c1SoRGroup)(*privateC1CommitReady,error){
    if len(groups)==0{return nil,errors.New("C1 verifier: no signed groups")}
    tracker:=&privateC1CommitReady{
        start:1,lastSeal:1,groups:make([]privateC1CommittedGroup,len(groups)),
        notifications:make(chan int,len(groups)),
    }
    for i,g:=range groups{
        if g.firstBatch<0||g.endBatch<=g.firstBatch||g.count<=0||g.bytes<=0{
            return nil,errors.New("C1 verifier: invalid signed reporting group")
        }
        if i>0 && g.firstBatch!=groups[i-1].endBatch{
            return nil,errors.New("C1 verifier: signed group batch gap")
        }
        tracker.groups[i]=privateC1CommittedGroup{
            firstBatch:g.firstBatch,endBatch:g.endBatch,expected:g.count,
        }
    }
    return tracker,nil
}

func startC1SoRParallelB(ctx context.Context,dsn string,
    frame c1handoff.Frame,ids []int64,pool *privateC1FiveSQL,
)(*privateC1CommitReady,*privateC1AsyncVerifier,error){
    if ctx==nil||pool==nil||len(ids)==0||frame.Kind!=c1handoff.Start{
        return nil,nil,errors.New("C1 verifier: uninitialized signed source")
    }
    // This session belongs ONLY to verifier B and is not in A's native SQL
    // worker pool. Independent READ ONLY transactions cannot modify SoR.
    conn,pid,err:=openC1SoRLocalSQL(ctx,dsn,"")
    if err!=nil{return nil,nil,err}
    closeOnError:=func(e error)(*privateC1CommitReady,*privateC1AsyncVerifier,error){
        _=conn.Close(context.Background())
        return nil,nil,e
    }
    if _,err=conn.Exec(ctx,"SET default_transaction_read_only = on");err!=nil{
        return closeOnError(err)
    }
    var transfer []byte
    receipt,e:=hex.DecodeString(frame.ReceiptSHA256)
    if e!=nil{return closeOnError(e)}
    err=conn.QueryRow(ctx,`SELECT transfer_sha256 FROM fi_recovery_projection.recorded_generation
        WHERE source_id=$1 AND generation_id=$2 AND receipt_sha256=$3`,
        frame.SourceID,frame.GenerationID,receipt).Scan(&transfer)
    if err!=nil||len(transfer)!=32{return closeOnError(errors.New("C1 verifier: original transfer evidence unavailable"))}
    batches:=make([]PreparedBatch,len(ids))
    indexBySQL:=make(map[int64]int,len(ids))
    for i,id:=range ids{indexBySQL[id]=i}
    rows,err:=conn.Query(ctx,`SELECT source_batch_id,batch_id,record_count,data_bytes,
        manifest_sha256,data_sha256
        FROM fi_recovery_projection.source_batch
        WHERE source_batch_id=ANY($1::bigint[])`,ids)
    if err!=nil{return closeOnError(err)}
    count:=0
    for rows.Next(){
        var id,records,size int64
        var name string
        var manifestSHA,dataSHA []byte
        if err=rows.Scan(&id,&name,&records,&size,&manifestSHA,&dataSHA);err!=nil{break}
        index,ok:=indexBySQL[id]
        if !ok||name!=frame.BatchIDs[index]||records<=0||size<=0||
            len(manifestSHA)!=32||len(dataSHA)!=32{
            err=errors.New("C1 verifier: signed batch SQL metadata or digest mismatch")
            break
        }
        batches[index]=PreparedBatch{BatchID:name,
            ManifestSHA256:hex.EncodeToString(manifestSHA),
            Manifest:spool.Manifest{BatchID:name,RecordCount:int(records),
                DataBytes:size,DataSHA256:hex.EncodeToString(dataSHA)}}
        count++
    }
    if err==nil{err=rows.Err()}
    rows.Close()
    if err!=nil{return closeOnError(err)}
    if count!=len(ids){return closeOnError(errors.New("C1 verifier: incomplete source manifest proof"))}
    groups,err:=c1SoRGroupPlan(batches,int(frame.StartBatchIndex))
    if err!=nil{return closeOnError(err)}
    var expected int64
    for _,g:=range groups{expected+=g.count}
    if expected!=frame.ExpectedRecords{
        return closeOnError(errors.New("C1 verifier: signed manifest group totals disagree with SoR Start"))
    }
    tracker,err:=c1SoRCommitTracker(groups)
    if err!=nil{return closeOnError(err)}
    g:=&PreparedGeneration{Batches:batches,ReceiptSHA256:frame.ReceiptSHA256}
    g.Receipt.TransferSHA256=hex.EncodeToString(transfer)
    g.Receipt.Descriptor.SourceID=frame.SourceID
    g.Receipt.Descriptor.GenerationID=frame.GenerationID
    ds:=make([]BacklogCheckpointDescriptor,len(groups)+1)
    ds[0].SourceID=frame.SourceID
    ds[0].GenerationID=frame.GenerationID
    ds[0].ReceiptSHA256=frame.ReceiptSHA256
    ds[0].TransferSHA256=g.Receipt.TransferSHA256
    for i,group:=range groups {
        ds[i+1]=BacklogCheckpointDescriptor{
            SourceID:frame.SourceID,GenerationID:frame.GenerationID,
            ReceiptSHA256:frame.ReceiptSHA256,
            TransferSHA256:g.Receipt.TransferSHA256,
            StartBatch:group.firstBatch,EndBatch:group.endBatch,
            EndRecord:uint64(group.count),DataBytes:uint64(group.bytes),
        }
    }
    v,err:=newPrivateC1AsyncVerifier(ctx,1,len(ds),tracker.notifications,
        func(c context.Context,wi int)error{
            return privateC1AsyncVerifyGroup(c,conn,g,ds,wi)
        },
        func(e error){fmt.Printf("FI C1 INDEPENDENT VERIFIER FAILURE error=%v acceptance=withheld sql_ingestion_cancelled=false\n",e)},
        len(groups)>1)
    if err!=nil{return closeOnError(err)}
    pool.commitReady=tracker
    go func(){<-v.done;_ =conn.Close(context.Background())}()
    fmt.Printf("FI C1 SOR PARALLEL VERIFIER START pid=%d groups=%d role=read_only independent_backend=true trigger=post_commit readiness_no_flush=true\n",
        pid,len(groups))
    _=time.Second // keep explicit time import for future scheduler timings
    return tracker,v,nil
}
