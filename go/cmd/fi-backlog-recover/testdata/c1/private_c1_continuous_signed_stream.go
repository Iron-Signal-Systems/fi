// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// C1 private-clone experiment: one bounded signed-record preparation stream
// over original receiver-authenticated cached batches. C1 does not calculate
// a second whole-batch data SHA-256; receiver custody owns that proof. C1
// checks manifest identity, byte/record counts and LF framing while consuming
// the exact cached source. There is no P6 batch or window flush.
package recordingest

import (
    "bufio"
    "bytes"
    "context"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "os"
    "time"
)

type privateC1StreamBatch struct {
    Index int
    Window int
    SourceBatchID int64
    Batch PreparedBatch
}

// privateC1SignedContinuousReader is one io.Reader for the entire selected
// signed generation, but never reads from batch N+1 before checking batch
// N's custody-bound manifest counts and framing. Only P5 stays continuous.
type privateC1SignedContinuousReader struct {
    batches []privateC1StreamBatch
    next int
    file *os.File
    readBytes int64
    readRecords int64
    lastByte byte
    completed int
    failed error
    onSealedGroup func(int)error // original custody-bound batch reaches complete count/byte/LF boundary
}

func newPrivateC1SignedContinuousReader(batches []privateC1StreamBatch) (*privateC1SignedContinuousReader,error) {
    if len(batches)==0{return nil,errors.New("FI C1 continuous: no signed batches")}
    for i,b:=range batches{
        if b.Index<0||b.SourceBatchID<=0||b.Window<1||b.Batch.DataPath==""||
            b.Batch.Manifest.RecordCount<=0||b.Batch.Manifest.DataBytes<=0{
            return nil,fmt.Errorf("FI C1 continuous: invalid batch descriptor at %d",i)
        }
        if i>0 && b.Index!=batches[i-1].Index+1{
            return nil,fmt.Errorf("FI C1 continuous: signed batch index discontinuity at %d",i)
        }
        digest,e:=hex.DecodeString(b.Batch.Manifest.DataSHA256)
        if e!=nil||len(digest)!=sha256.Size{
            return nil,fmt.Errorf("FI C1 continuous: invalid signed data SHA at batch %d",b.Index)
        }
    }
    return &privateC1SignedContinuousReader{batches:batches},nil
}

func(s *privateC1SignedContinuousReader) openNext()error{
    b:=s.batches[s.next]
    f,err:=os.Open(b.Batch.DataPath)
    if err!=nil{return fmt.Errorf("FI C1 continuous: batch %d open: %w",b.Index,err)}
    stat,err:=f.Stat()
    if err!=nil||!stat.Mode().IsRegular()||stat.Size()!=b.Batch.Manifest.DataBytes{
        _=f.Close()
        return fmt.Errorf("FI C1 continuous: signed batch %d original data file changed (stat=%v)",b.Index,err)
    }
    s.file=f
    s.readBytes=0
    s.readRecords=0
    s.lastByte=0
    return nil
}

func(s *privateC1SignedContinuousReader) finishBatch()error{
    b:=s.batches[s.next]
    valid:=s.readBytes==b.Batch.Manifest.DataBytes &&
        s.readRecords==int64(b.Batch.Manifest.RecordCount) &&
        s.lastByte=='\n'
    closeErr:=s.file.Close()
    s.file=nil
    if !valid{
        return fmt.Errorf("FI C1 continuous: signed batch %d count/bytes/LF mismatch got_records=%d expected_records=%d got_bytes=%d expected_bytes=%d",
            b.Index,s.readRecords,b.Batch.Manifest.RecordCount,s.readBytes,b.Batch.Manifest.DataBytes)
    }
    if closeErr!=nil{
        return fmt.Errorf("FI C1 continuous: signed batch %d close: %w",b.Index,closeErr)
    }
    s.next++
    s.completed++
    if s.onSealedGroup!=nil &&
       (s.next==len(s.batches)||s.batches[s.next].Window!=b.Window){
        if err:=s.onSealedGroup(b.Window);err!=nil{
            return fmt.Errorf("FI C1 continuous: group %d completed custody-bound batch handoff: %w",b.Window,err)
        }
    }
    return nil
}

// Read intentionally returns after bytes from one signed batch. The next
// call sees EOF, verifies that original batch, and only then opens the next.
// Header-first parsing and P5 worker preparation remain continuous.
func(s *privateC1SignedContinuousReader) Read(p []byte)(int,error){
    if s==nil{return 0,errors.New("FI C1 continuous: nil reader")}
    if len(p)==0{return 0,nil}
    if s.failed!=nil{return 0,s.failed}
    for{
        if s.file==nil{
            if s.next==len(s.batches){return 0,io.EOF}
            if err:=s.openNext();err!=nil{s.failed=err;return 0,err}
        }
        n,err:=s.file.Read(p)
        if n>0{
            s.readBytes+=int64(n)
            s.readRecords+=int64(bytes.Count(p[:n],[]byte{'\n'}))
            s.lastByte=p[n-1]
            if s.readBytes>s.batches[s.next].Batch.Manifest.DataBytes{
                s.failed=fmt.Errorf("FI C1 continuous: signed batch %d exceeded manifest bytes",s.batches[s.next].Index)
                return 0,s.failed
            }
            if err!=nil&&!errors.Is(err,io.EOF){
                s.failed=fmt.Errorf("FI C1 continuous: signed batch %d read: %w",s.batches[s.next].Index,err)
                return 0,s.failed
            }
            return n,nil
        }
        if errors.Is(err,io.EOF){
            if checkErr:=s.finishBatch();checkErr!=nil{
                s.failed=checkErr
                return 0,checkErr
            }
            continue
        }
        if err!=nil{
            s.failed=fmt.Errorf("FI C1 continuous: signed batch %d read: %w",s.batches[s.next].Index,err)
            return 0,s.failed
        }
        // io.Reader permits a zero-byte successful read; the canonical
        // dispatcher already enforces a bounded no-progress guard.
        return 0,nil
    }
}

func(s *privateC1SignedContinuousReader) VerifyComplete()error{
    if s==nil{return errors.New("FI C1 continuous: nil signed source")}
    if s.failed!=nil{return s.failed}
    if s.file!=nil||s.next!=len(s.batches)||s.completed!=len(s.batches){
        return fmt.Errorf("FI C1 continuous: incomplete signed source completed=%d expected=%d",s.completed,len(s.batches))
    }
    return nil
}

func(s *privateC1SignedContinuousReader) Close()error{
    if s==nil||s.file==nil{return nil}
    err:=s.file.Close()
    s.file=nil
    return err
}

// The original P5 workers, 32-record credits, 256MiB byte admission,
// signed ordinal delivery and five P6 families remain unchanged. This uses
// ONE preparation stream for the entire replay, not one per signed batch.
func privateC1ConsumeContinuousSigned(ctx context.Context,pool *privateP5Pool,
    batches []privateC1StreamBatch,buffers *privateP6Buffers,
    totals *privateC1PrepTotals,windowCount int,
    prepare privateHeaderPrepareFunc,
    onSealedGroup func(int)error,
)([]int64,[]int64,error){
    if ctx==nil||pool==nil||buffers==nil||totals==nil||prepare==nil||windowCount<2{
        return nil,nil,errors.New("FI C1 continuous: invalid P5/P6 input")
    }
    source,err:=newPrivateC1SignedContinuousReader(batches)
    if err!=nil{return nil,nil,err}
    source.onSealedGroup=onSealedGroup
    // The signed input reader may block while waiting for the next prepared
    // record. Keep Next on ONE goroutine and all family buffers/SQL flushes
    // on the consumer goroutine, where a 1s tick runs independently of input.
    consumerCtx,cancelConsumer:=context.WithCancel(ctx)
    stream,err:=pool.newStream(consumerCtx,bufio.NewReaderSize(source,128<<10),prepare)
    if err!=nil{cancelConsumer();_ =source.Close();return nil,nil,err}
    incoming:=make(chan privateParallelLine,1)
    readerDone:=make(chan struct{})
    go func(){
        defer close(incoming)
        defer close(readerDone)
        for{
            line,ok:=stream.Next()
            if !ok{return}
            select{
            case <-consumerCtx.Done():return
            case incoming<-line:
            }
        }
    }()
    defer func(){
        cancelConsumer()
        stream.Close()
        <-readerDone
        _ =source.Close()
    }()
    ticker:=time.NewTicker(privateC1FamilyIdlePollInterval)
    defer ticker.Stop()
    fmt.Printf("FI C1 FAMILY PROCESSING INACTIVITY TIMER timeout=%s poll=%s per_family=true resets_on=received_record no_input_required=true owner=ordered_consumer no_batch_flush=true no_group_flush=true\n",
        buffers.idleTimeout,privateC1FamilyIdlePollInterval)
    rows:=make([]int64,windowCount)
    sizes:=make([]int64,windowCount)
    batchCursor:=0
    var localOrdinal,localBytes,globalOrdinal int64
    for{
        if err:=ctx.Err();err!=nil{return nil,nil,err}
        var line privateParallelLine
        var ok bool
        select{
        case <-ctx.Done():
            return nil,nil,ctx.Err()
        case <-ticker.C:
            if err:=buffers.flushIdleFamilies(ctx,time.Now());err!=nil{
                return nil,nil,fmt.Errorf("FI C1: 30-second Family Processing inactivity flush: %w",err)
            }
            continue
        case line,ok=<-incoming:
            if !ok{break}
        }
        if !ok{break}
        if line.readErr!=nil{return nil,nil,fmt.Errorf("FI C1 continuous: reader: %w",line.readErr)}
        if line.prepareErr!=nil{return nil,nil,fmt.Errorf("FI C1 continuous: preparation: %w",line.prepareErr)}
        if batchCursor>=len(batches){
            return nil,nil,errors.New("FI C1 continuous: more records than signed manifests")
        }
        b:=batches[batchCursor]
        globalOrdinal++
        localOrdinal++
        if line.ordinal!=globalOrdinal||localOrdinal>int64(b.Batch.Manifest.RecordCount){
            return nil,nil,fmt.Errorf("FI C1 continuous: signed order mismatch batch=%d ordinal=%d global=%d",b.Index,localOrdinal,line.ordinal)
        }
        if line.source.RecordBytes!=len(line.raw)||
            len(line.source.RawRecordBytes)!=len(line.raw)||
            line.source.Record.RecordKind!=line.headerKind{
            return nil,nil,fmt.Errorf("FI C1 continuous: prepared record differs from signed bytes batch=%d ordinal=%d",b.Index,localOrdinal)
        }
        if err=buffers.Add(ctx,privateP6Record{
            signedBatchIndex:b.Index,sourceBatchID:b.SourceBatchID,ordinal:localOrdinal,
            prepared:line.source,selectedSinglePass:line.selected,
            singlePassSecurity:line.security,
        });err!=nil{return nil,nil,err}
        localBytes+=int64(len(line.raw))
        rows[b.Window]++
        sizes[b.Window]+=int64(len(line.raw))
        if localOrdinal==int64(b.Batch.Manifest.RecordCount){
            if localBytes!=b.Batch.Manifest.DataBytes{
                return nil,nil,fmt.Errorf("FI C1 continuous: signed batch %d prepared bytes mismatch got=%d expected=%d",
                    b.Index,localBytes,b.Batch.Manifest.DataBytes)
            }
            batchCursor++
            localOrdinal=0
            localBytes=0
        }
    }
    if err=source.VerifyComplete();err!=nil{return nil,nil,err}
    if batchCursor!=len(batches)||localOrdinal!=0||localBytes!=0{
        return nil,nil,fmt.Errorf("FI C1 continuous: signed batch completion mismatch complete=%d expected=%d",
            batchCursor,len(batches))
    }
    totals.batches+=int64(batchCursor)
    totals.records+=globalOrdinal
    totals.readerTime+=stream.readerTime
    totals.workerTime+=stream.workerTime
    totals.writerWait+=stream.waits
    fmt.Printf("FI C1 P5 CONTINUOUS SIGNED STREAM PASS batches=%d sessions=1 records=%d sealed_batches=%d custody_sha256=receiver_verified per_batch_manifest=true exact_ordinals=true buffers=bounded\n",
        batchCursor,globalOrdinal,source.completed)
    return rows,sizes,nil
}
