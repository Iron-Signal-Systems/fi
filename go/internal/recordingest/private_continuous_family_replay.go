// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Experimental signed-cache replay through durable source-first family lanes.
// No authoritative FI table may be used as a destination; the private sink
// rewrites every relational projector to fi_recovery_projection.
package recordingest

import (
    "context"
    "errors"
    "fmt"

    "github.com/jackc/pgx/v5"
)

// StageBacklogContinuousFamilyWindows replays only an explicitly bounded
// contiguous range. A preceding typed-window marker MUST already exist for
// start>0 (normally the independently verified W0-W2 fixture).
//
// Source checkpoints commit before typed buffering. A W128 source boundary
// never empties a partially filled family; EndOfInput is the only final drain.
// This DEV ONLY function is not a generation acceptance or promotion API.
func StageBacklogContinuousFamilyWindows(ctx context.Context, writer *pgx.Conn,
    generation *PreparedGeneration, limits BacklogWindowLimits,
    start, windows int, privateRoot string) error {
    if ctx==nil || writer==nil || generation==nil || windows<=0 || start<0 {
        return errors.New("FI continuous family replay: invalid source or bounded window range")
    }
    descriptions,err:=DescribeBacklogWindows(generation,limits)
    if err!=nil{return err}
    if start>=len(descriptions) || windows>len(descriptions)-start {
        return errors.New("FI continuous family replay: requested windows outside authenticated generation")
    }
    if err=verifyPrivateBacklogRoot(privateRoot);err!=nil{return err}
    sink,err:=newPrivateContinuousPostgresSink(ctx,writer,generation,limits)
    if err!=nil{return fmt.Errorf("FI continuous family replay: private SQL setup: %w",err)}
    if start>0 {
        prior:=descriptions[start-1]
        digest,err:=decodeHex(prior.DigestSHA256,32,true,"prior typed window digest")
        if err!=nil{return err}
        var stored []byte
        err=writer.QueryRow(ctx,`SELECT descriptor_sha256 FROM fi_recovery.typed_window
            WHERE receipt_sha256=$1 AND window_index=$2`,sink.receipt,start-1).Scan(&stored)
        if err!=nil{return fmt.Errorf("FI continuous family replay: missing verified typed seed: %w",err)}
        if !bytesEqual(stored,digest) {
            return errors.New("FI continuous family replay: typed seed digest mismatch")
        }
    }
    router,err:=newPrivateContinuousFamilyRouter(ctx,sink,start-1)
    if err!=nil{return err}
    for index:=start;index<start+windows;index++ {
        if err=ctx.Err();err!=nil{return err}
        d:=descriptions[index]
        // Original signed bytes, artifact ledger and source SQL checkpoint
        // are verified and committed BEFORE the first typed buffer Add.
        if _,err=MaterializeBacklogWindow(ctx,generation,limits,index,privateRoot);err!=nil {
            return fmt.Errorf("FI continuous family replay: materialize W%d: %w",index,err)
        }
        if err=RecordVerifiedBacklogArtifactWindow(ctx,writer,generation,limits,index,privateRoot);err!=nil {
            return fmt.Errorf("FI continuous family replay: artifact W%d: %w",index,err)
        }
        if err=StageVerifiedBacklogSourceWindow(ctx,writer,generation,limits,index,privateRoot);err!=nil {
            return fmt.Errorf("FI continuous family replay: source W%d: %w",index,err)
        }
        if err=router.BeginSourceWindow(ctx,index);err!=nil{return err}
        digest,records,bytes,err:=scanBacklogWindowRecords(ctx,generation,d,index,privateRoot,
            func(batchIndex int,ordinal int64,item SourceRecord) error {
                return router.Add(ctx,privateContinuousRecord{
                    WindowIndex:index,SignedBatchIndex:batchIndex,Ordinal:ordinal,
                    SourceBatchID:sink.batchIDs[batchIndex],Prepared:item})
            })
        if err!=nil{return fmt.Errorf("FI continuous family replay: signed W%d: %w",index,err)}
        if records!=d.EndRecord-d.StartRecord || bytes!=d.DataBytes || len(digest)!=32 {
            return fmt.Errorf("FI continuous family replay: signed W%d totals invalid",index)
        }
        if err=router.EndSourceWindow(ctx,index);err!=nil{return err}
        fmt.Printf("FI PRIVATE CONTINUOUS SOURCE WINDOW window=%d records=%d bytes=%d pending=%d typed_through=%d\n",
            index,records,bytes,router.outstanding[index],router.confirmedThrough)
    }
    if err=router.EndOfInput(ctx);err!=nil{return err}
    if router.confirmedThrough!=start+windows-1 {
        return errors.New("FI continuous family replay: incomplete typed window prefix")
    }
    fmt.Printf("FI PRIVATE CONTINUOUS FAMILY PASS windows=%d..%d typed_through=%d authoritative=0 accepted=0\n",
        start,start+windows-1,router.confirmedThrough)
    return nil
}
