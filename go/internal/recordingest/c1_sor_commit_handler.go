//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// The fi-sor jail, not fi-ingest, consumes the C1 signed handoff and owns
// every PostgreSQL transaction. This is the server-side SQL phase.
package recordingest

import (
    "context"
    "errors"
    "fmt"
    "strings"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)

type c1SoRSQLWriter interface {
    Source(context.Context,[]privateP6Record)error
    Family(context.Context,privateP6Family,[]privateP6Record)error
    WaitSource(context.Context)error
    WaitFamily(context.Context,privateP6Family)error
    WaitAll(context.Context)error
}
type c1SoRCommitHandler struct {
    sink c1SoRSQLWriter
    sourceID,generationID,receipt string
    // These IDs are looked up from FI's verified original signed source
    // batches by fi-sor; NEVER accept an arbitrary identity from fi-ingest.
    sourceBatches []int64
    batchRecordCounts []int64 // immutable original signed per-batch manifest counts
    parentBatchCounts []int64 // source rows admitted/committed for each non-seed batch
    typedBatchCounts []int64 // typed row admissions from every projector, counted by signed batch
    typedSeen [][]uint64 // one bit per signed ordinal, bounded by immutable manifest counts
    minBatchIndex uint32 // immutable signed prefix cannot be reprojected
    expectedRecords int64
    parentRows int64
    typedRows int64
    lastParentBatch uint32
    lastParentOrdinal int64
    drained bool
}
func newC1SoRCommitHandler(
    sink c1SoRSQLWriter, sourceID,generationID,receipt string,
    sourceBatches,batchRecordCounts []int64,expectedRecords int64,
)(*c1SoRCommitHandler,error){
    if sink==nil||sourceID==""||generationID==""||len(receipt)!=64||
        len(sourceBatches)==0||len(batchRecordCounts)!=len(sourceBatches)||
        expectedRecords<=0 {
        return nil,errors.New("C1 fi-sor: original signed generation plan or SQL processor missing")
    }
    for i,id:=range sourceBatches{
        if id<=0||batchRecordCounts[i]<=0{
            return nil,errors.New("C1 fi-sor: missing original signed source-batch identity or record count")
        }
    }
    // One bit per source ordinal is enough to reject duplicate typed
    // coverage across independent SQL families. Bound total memory based on
    // original fi-sor manifest counts, not client-supplied allocations.
    const maxCoverageBytes int64=64<<20
    var coverageBytes int64
    for _,count:=range batchRecordCounts{
        words:=count/64
        if count%64!=0{words++}
        if words>maxCoverageBytes/8-coverageBytes/8{
            return nil,errors.New("C1 fi-sor: original signed per-ordinal coverage exceeds bounded memory")
        }
        coverageBytes+=words*8
    }
    return &c1SoRCommitHandler{sink:sink,sourceID:sourceID,
        generationID:generationID,receipt:strings.ToLower(receipt),
        sourceBatches:append([]int64(nil),sourceBatches...),
        batchRecordCounts:append([]int64(nil),batchRecordCounts...),
        parentBatchCounts:make([]int64,len(sourceBatches)),
        typedBatchCounts:make([]int64,len(sourceBatches)),
        typedSeen:make([][]uint64,len(sourceBatches)),
        expectedRecords:expectedRecords},nil
}
func (s *c1SoRCommitHandler) Commit(ctx context.Context,f c1handoff.Frame)error{
    if s==nil||ctx==nil||s.sink==nil||s.drained {
        return errors.New("C1 fi-sor: inactive or already drained SQL session")
    }
    if err:=f.Validate();err!=nil{return err}
    if f.SourceID!=s.sourceID||f.GenerationID!=s.generationID||
        f.ReceiptSHA256!=s.receipt {
        return errors.New("C1 fi-sor: signed generation/receipt changed across jail boundary")
    }
    if f.Kind==c1handoff.Ack {return errors.New("C1 fi-sor: client supplied forged commit ACK")}
    if f.Kind==c1handoff.Drain{
        if err:=s.sink.WaitAll(ctx);err!=nil{return fmt.Errorf("C1 fi-sor: incomplete SQL workers: %w",err)}
        if s.parentRows!=s.expectedRecords||s.typedRows!=s.expectedRecords{
            return fmt.Errorf("C1 fi-sor: refused incomplete drain parents=%d typed=%d signed=%d",
                s.parentRows,s.typedRows,s.expectedRecords)
        }
        for i:=int(s.minBatchIndex);i<len(s.batchRecordCounts);i++{
            if s.parentBatchCounts[i]!=s.batchRecordCounts[i]||
                s.typedBatchCounts[i]!=s.batchRecordCounts[i]{
                return fmt.Errorf("C1 fi-sor: signed source batch %d incomplete parents=%d typed=%d expected=%d",
                    i,s.parentBatchCounts[i],s.typedBatchCounts[i],s.batchRecordCounts[i])
            }
        }
        s.drained=true
        return nil
    }
    rows,err:=s.prepareRows(f)
    if err!=nil{return err}
    if f.Kind==c1handoff.Source{
        if err:=s.sink.Source(ctx,rows);err!=nil{return err}
        // C1's ordered PostgreSQL source writer commits inside fi-sor.
        if err:=s.sink.WaitSource(ctx);err!=nil{return err}
        s.accountSource(rows)
        return nil
    }
    family:=privateP6Family(f.Kind-2)
    if err:=s.sink.Family(ctx,family,rows);err!=nil{return err}
    if err:=s.sink.WaitFamily(ctx,family);err!=nil{return err}
    s.accountTyped(rows)
    return nil
}
// prepareRows maps every signed original batch/ordinal to its exact
// validated C1 projector family. It performs NO PostgreSQL write, and is
// reused identically by synchronous tests and the native async SQL path.
func(s *c1SoRCommitHandler)prepareRows(f c1handoff.Frame)([]privateP6Record,error){
    if s==nil||s.sink==nil||s.drained{
        return nil,errors.New("C1 fi-sor: inactive or already drained session")
    }
    if err:=f.Validate();err!=nil{return nil,err}
    if f.SourceID!=s.sourceID||f.GenerationID!=s.generationID||
        f.ReceiptSHA256!=s.receipt{
        return nil,errors.New("C1 fi-sor: mismatched signed generation")
    }
    if f.Kind<c1handoff.Source||f.Kind>c1handoff.Other{
        return nil,errors.New("C1 fi-sor: expected original signed SQL handoff")
    }
    rows:=make([]privateP6Record,0,len(f.Rows))
    // Detect intra-handoff duplicate ordinals before SQL admission, and
    // prevent all cross-handoff/cross-family duplicate typed coverage.
    // Ordered parent frames have their own stricter contiguous-range proof.
    type originalOrdinal struct{ batch int; ordinal int64 }
    localSeen:=make(map[originalOrdinal]struct{},len(f.Rows))
    for i,row:=range f.Rows {
        index:=int(row.SignedBatchIndex)
        if index<int(s.minBatchIndex)||index>=len(s.sourceBatches)||
            row.SourceBatchID!=s.sourceBatches[index] {
            return nil,fmt.Errorf("C1 fi-sor: row %d is not mapped to verified signed batch",i)
        }
        if f.Kind!=c1handoff.Source{
            if row.Ordinal<=0||row.Ordinal>s.batchRecordCounts[index]{
                return nil,fmt.Errorf("C1 fi-sor: typed ordinal %d exceeds signed batch %d",row.Ordinal,index)
            }
            position:=originalOrdinal{batch:index,ordinal:row.Ordinal}
            if _,ok:=localSeen[position];ok{
                return nil,errors.New("C1 fi-sor: duplicate typed signed ordinal within SQL handoff")
            }
            localSeen[position]=struct{}{}
            bits:=s.typedSeen[index]
            if len(bits)>0 && bits[(row.Ordinal-1)/64]&(uint64(1)<<uint((row.Ordinal-1)%64))!=0{
                return nil,errors.New("C1 fi-sor: duplicate typed signed ordinal across SQL handoffs")
            }
        }
        prepared,err:=PrepareSourceRecord(row.RawRecord)
        if err!=nil{return nil,fmt.Errorf("C1 fi-sor: signed source decode %d: %w",i,err)}
        if prepared.RecordDigest!=row.Digest {
            return nil,errors.New("C1 fi-sor: prepared record differs from signed source digest")
        }
        family,err:=privateP6KindFamily(prepared.Record.RecordKind)
        if err!=nil{return nil,err}
        if f.Kind!=c1handoff.Source && f.Kind!=c1handoff.Kind(family+2){
            return nil,errors.New("C1 fi-sor: wrong native SQL projector for signed record kind")
        }
        if f.Kind==c1handoff.Source{
            // A signed batch starts at ordinal 1 and every subsequent
            // SourceParent is contiguous. Counts come from fi-sor's own
            // previously validated source_batch rows, never the client.
            expectedOrdinal:=int64(1)
            precedingBatch:=int(s.minBatchIndex)-1
            if s.parentRows>0{
                precedingBatch=int(s.lastParentBatch)
                if i==0 && index==precedingBatch{
                    expectedOrdinal=s.lastParentOrdinal+1
                }
            }
            if i>0{
                precedingBatch=int(f.Rows[i-1].SignedBatchIndex)
                if index==precedingBatch{
                    expectedOrdinal=f.Rows[i-1].Ordinal+1
                }
            }
            if index<precedingBatch||index>precedingBatch+1||
                row.Ordinal!=expectedOrdinal||
                row.Ordinal>s.batchRecordCounts[index]{
                return nil,fmt.Errorf("C1 fi-sor: signed source batch %d ordinal %d violates original contiguous range (next=%d max=%d)",
                    index,row.Ordinal,expectedOrdinal,s.batchRecordCounts[index])
            }
        }
        rows=append(rows,privateP6Record{
            signedBatchIndex:index,sourceBatchID:row.SourceBatchID,
            ordinal:row.Ordinal,prepared:prepared,
        })
    }
    if int64(len(rows))>s.expectedRecords-s.parentRows && f.Kind==c1handoff.Source{
        return nil,errors.New("C1 fi-sor: source-parent committed rows would exceed original signed receipt")
    }
    // No family may outrun the durable SourceParent ledger. The SQL
    // foreign-key proof below remains authoritative for exact identity.
    if f.Kind!=c1handoff.Source && int64(len(rows))>s.parentRows-s.typedRows {
        return nil,errors.New("C1 fi-sor: typed family outran committed source parents")
    }
    if int64(len(rows))>s.expectedRecords-s.typedRows && f.Kind!=c1handoff.Source{
        return nil,errors.New("C1 fi-sor: family committed rows would exceed original signed receipt")
    }
    return rows,nil
}
// Only advance source admission after the SQL sink has accepted the
// handoff. In async mode this is provisional until WaitAll proves all
// PostgreSQL COMMIT fences; in sync mode it follows WaitSource.
func(s *c1SoRCommitHandler)accountSource(rows []privateP6Record){
    s.parentRows+=int64(len(rows))
    for _,r:=range rows{s.parentBatchCounts[r.signedBatchIndex]++}
    last:=rows[len(rows)-1]
    s.lastParentBatch=uint32(last.signedBatchIndex)
    s.lastParentOrdinal=last.ordinal
}

// On successful typed admission, reserve each signed ordinal once across
// all five family workers. PostgreSQL commit futures remain authoritative
// for durability; this bitmap is only an in-session completeness invariant.
func(s *c1SoRCommitHandler)accountTyped(rows []privateP6Record){
    s.typedRows+=int64(len(rows))
    for _,r:=range rows{
        i:=r.signedBatchIndex
        if s.typedSeen[i]==nil{
            s.typedSeen[i]=make([]uint64,(s.batchRecordCounts[i]+63)/64)
        }
        pos:=r.ordinal-1
        s.typedSeen[i][pos/64]|=uint64(1)<<uint(pos%64)
        s.typedBatchCounts[i]++
    }
}

// Keep signed-batch indexes as the exact original metadata, not PostgreSQL
// sequence position. No synthetic per-family ordinal is ever introduced.
func(r privateP6Record)signedBatchIndexAsUint()uint32{return uint32(r.signedBatchIndex)}
var _ c1SoRSQLWriter=(*privateC1FiveSQL)(nil)
