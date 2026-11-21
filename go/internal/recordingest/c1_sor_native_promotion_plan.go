//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Reconstruct C1's original signed generation from ONLY read-only fi-sor
// PostgreSQL stage metadata and its separate immutable signed receipt.
// This cannot publish anything, fabricate a checkpoint, modify custody or
// open a network PostgreSQL connection. B rechecks all evidence under locks.
package recordingest

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "fmt"
    "math"
    "path/filepath"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
    "github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/jackc/pgx/v5"
)

func c1BuildFullNativePromotionPlan(source,generation,receipt,transfer string,
    ids []int64,batches []PreparedBatch)(c1NativeBPlan,error){
    var p c1NativeBPlan
    if source==""||generation==""||!canonicalDigest(receipt)||
        !canonicalDigest(transfer)||len(ids)==0||len(ids)!=len(batches){
        return p,errors.New("C1 promotion: incomplete signed SQL batch mapping")
    }
    var count int64
    batchNames:=make([]string,len(batches))
    for i,b:=range batches{
        if ids[i]<=0||b.BatchID==""||b.Manifest.RecordCount<=0||
            b.Manifest.DataBytes<=0||!canonicalDigest(b.ManifestSHA256)||
            !canonicalDigest(b.Manifest.DataSHA256)||
            int64(b.Manifest.RecordCount)>math.MaxInt64-count{
            return p,errors.New("C1 promotion: malformed or overflowing signed private source-batch metadata")
        }
        if i>0&&b.BatchID<=batches[i-1].BatchID{
            return p,errors.New("C1 promotion: private signed batch IDs missing or out of order")
        }
        count+=int64(b.Manifest.RecordCount)
        batchNames[i]=b.BatchID
    }
    p.Start=c1handoff.Frame{Kind:c1handoff.Start,Sequence:1,
        SourceID:source,GenerationID:generation,ReceiptSHA256:receipt,
        StartBatchIndex:0,ExpectedRecords:count,BatchIDs:batchNames}
    p.SQLIDs=append([]int64(nil),ids...)
    p.Batches=append([]PreparedBatch(nil),batches...)
    p.Transfer=transfer
    groups,err:=c1SoRGroupPlan(batches,0)
    if err!=nil{return c1NativeBPlan{},err}
    p.Descriptors=make([]BacklogCheckpointDescriptor,len(groups)+1)
    p.Descriptors[0]=BacklogCheckpointDescriptor{
        SourceID:source,GenerationID:generation,
        ReceiptSHA256:receipt,TransferSHA256:transfer,EndBatch:0,
    }
    var records uint64
    for i,g:=range groups{
        start:=records
        records+=uint64(g.count)
        p.Descriptors[i+1]=BacklogCheckpointDescriptor{
            SourceID:source,GenerationID:generation,
            ReceiptSHA256:receipt,TransferSHA256:transfer,
            StartBatch:g.firstBatch,EndBatch:g.endBatch,
            StartRecord:start,EndRecord:records,DataBytes:uint64(g.bytes),
        }
    }
    if err:=c1ValidateNativeBPlan(p);err!=nil{return c1NativeBPlan{},err}
    return p,nil
}

// LoadC1NativePromotionPlan never trusts network START metadata for
// publication. Independently compute receipt hash from the immutable
// recorder file, then look up the exact private source_batch SQL ledger.
func LoadC1NativePromotionPlan(ctx context.Context,conn *pgx.Conn,
    source,generation string,custody c1NativeBCustodyConfig)(c1NativeBPlan,error){
    var empty c1NativeBPlan
    if ctx==nil||conn==nil||source==""||generation==""||
        custody.RecordedRoot==""||!filepath.IsAbs(custody.RecordedRoot){
        return empty,errors.New("C1 promotion: original receiver source and signed receipt required")
    }
    root:=custody.RecordedRoot
    if custody.SourceNamespaces{
        var err error
        root,err=generationrecorder.RecordedSourceDirectory(root,source)
        if err!=nil{return empty,err}
    }
    receiptRaw,err:=readImmutableReceipt(filepath.Join(root,
        generationrecorder.RecordedReceiptObjectName(source,generation)))
    if err!=nil{return empty,err}
    receiptSHA:=sha256.Sum256(receiptRaw)
    receipt,err:=generationrecorder.UnmarshalRecordedReceipt(receiptRaw)
    if err!=nil{return empty,err}
    if receipt.Descriptor.SourceID!=source||
        receipt.Descriptor.GenerationID!=generation{
        return empty,errors.New("C1 promotion: signed recorder receipt describes another generation")
    }
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly})
    if err!=nil{return empty,err}
    defer tx.Rollback(context.Background())
    var recordedID,storedRecords,storedBatches int64
    var transfer []byte
    err=tx.QueryRow(ctx,`SELECT recorded_generation_id,record_count,batch_count,transfer_sha256
        FROM fi_recovery_projection.recorded_generation
        WHERE source_id=$1 AND generation_id=$2 AND receipt_sha256=$3`,
        source,generation,receiptSHA[:]).
        Scan(&recordedID,&storedRecords,&storedBatches,&transfer)
    if err!=nil{return empty,fmt.Errorf("C1 promotion: missing exact private signed generation: %w",err)}
    if recordedID<=0||storedRecords<=0||storedBatches<=0||
        storedBatches>65535||len(transfer)!=32{
        return empty,errors.New("C1 promotion: invalid original private generation metadata")
    }
    rows,err:=tx.Query(ctx,`SELECT source_batch_id,batch_id,record_count,
         data_bytes,manifest_sha256,data_sha256
         FROM fi_recovery_projection.source_batch
         WHERE recorded_generation_id=$1 ORDER BY batch_id`,recordedID)
    if err!=nil{return empty,err}
    ids:=make([]int64,0,storedBatches)
    batches:=make([]PreparedBatch,0,storedBatches)
    var n int64
    for rows.Next(){
        var id,count,size int64
        var name string
        var manifestHash,dataHash []byte
        if err=rows.Scan(&id,&name,&count,&size,&manifestHash,&dataHash);err!=nil{break}
        if id<=0||name==""||count<=0||count>math.MaxInt32||size<=0||
            len(manifestHash)!=32||len(dataHash)!=32{
            err=errors.New("C1 promotion: corrupt private original source batch")
            break
        }
        ids=append(ids,id)
        batches=append(batches,PreparedBatch{
            BatchID:name,ManifestSHA256:hex.EncodeToString(manifestHash),
            Manifest:spool.Manifest{BatchID:name,RecordCount:int(count),
                DataBytes:size,DataSHA256:hex.EncodeToString(dataHash)},
        })
        n+=count
        if n>storedRecords||len(ids)>int(storedBatches){
            err=errors.New("C1 promotion: private batch record sum exceeded signed receipt")
            break
        }
    }
    if err==nil{err=rows.Err()}
    rows.Close()
    if err!=nil{return empty,err}
    if int64(len(ids))!=storedBatches||n!=storedRecords||
        receipt.BatchCount!=uint64(storedBatches)||
        receipt.RecordCount!=uint64(storedRecords)||
        receipt.TransferSHA256!=hex.EncodeToString(transfer){
        return empty,errors.New("C1 promotion: original signed receipt and private batch ledger disagree")
    }
    if err=tx.Commit(ctx);err!=nil{return empty,err}
    return c1BuildFullNativePromotionPlan(source,generation,
        hex.EncodeToString(receiptSHA[:]),hex.EncodeToString(transfer),ids,batches)
}

// PublishC1VerifiedPrivateGeneration is a distinct, OFFLINE fi-sor command
// invoked AFTER the development ingestion session and independent verifier
// B have closed. The recorded receipt reconstructs the FULL source plan;
// the atomic promoter repeats original custody/typed proof under SQL locks.
// No tmpfs transport, fi-ingest PostgreSQL access, or second SQL ingestion
// algorithm is involved.
func PublishC1VerifiedPrivateGeneration(ctx context.Context,dsn string,
    custody c1NativeBCustodyConfig,source,generation,attemptID string)(
    IngestResult,error){
    var empty IngestResult
    if ctx==nil||source==""||generation==""||attemptID==""{
        return empty,errors.New("C1 publication: source, generation, attempt and context required")
    }
    verifier,_,err:=openC1SoRLocalSQL(ctx,dsn,"")
    if err!=nil{return empty,fmt.Errorf("C1 publication: read-only verifier local SQL: %w",err)}
    defer verifier.Close(context.Background())
    publisher,_,err:=openC1SoRLocalSQL(ctx,dsn,"")
    if err!=nil{return empty,fmt.Errorf("C1 publication: canonical publisher local SQL: %w",err)}
    defer publisher.Close(context.Background())
    if verifier.PgConn().PID()==publisher.PgConn().PID(){
        return empty,errors.New("C1 publication: independent PostgreSQL sessions required")
    }
    plan,err:=LoadC1NativePromotionPlan(ctx,verifier,source,generation,custody)
    if err!=nil{return empty,err}
    return PromoteC1VerifiedToPopulatedSoR(ctx,verifier,publisher,
        plan,custody,attemptID)
}
