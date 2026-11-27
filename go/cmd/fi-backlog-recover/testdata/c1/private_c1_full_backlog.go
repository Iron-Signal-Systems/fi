// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "crypto/subtle"
    "encoding/hex"
    "errors"
    "fmt"
    "math"

    "github.com/jackc/pgx/v5"
)

// privateC1VerifyCompleteGroupedReplay checks the clone-only complete C1
// relational replay. It does NOT attest complete three-ledger source/artifact
// recovery and MUST NOT be used as an Accepted or published generation proof.
// The new groups carry typed markers only. Per-group source identity and full
// relational coverage are verified transactionally before those markers are
// recorded by privateC1MarkTyped. This adds a read-only whole-generation
// digest, record, and anti-publication check over all signed source batches.
func privateC1VerifyCompleteGroupedReplay(ctx context.Context, conn *pgx.Conn,
    g *PreparedGeneration, ds []BacklogCheckpointDescriptor,
)(BacklogGenerationVerification,error) {
    var empty BacklogGenerationVerification
    if ctx==nil || conn==nil || g==nil || len(ds)<3 ||
        g.Receipt.BatchCount!=uint64(len(g.Batches)) ||
        g.Receipt.RecordCount==0 || g.Receipt.DataBytes==0 ||
        g.Receipt.RecordCount>math.MaxInt64 || g.Receipt.DataBytes>math.MaxInt64 {
        return empty,errors.New("FI C1 FULL: invalid grouped signed-generation verification input")
    }
    if err:=ctx.Err();err!=nil{return empty,err}
    if ds[0].StartBatch!=0 || ds[0].StartRecord!=0 ||
        ds[len(ds)-1].EndBatch!=len(g.Batches) ||
        ds[len(ds)-1].EndRecord!=g.Receipt.RecordCount ||
        ds[0].ReceiptSHA256!=g.ReceiptSHA256 {
        return empty,errors.New("FI C1 FULL: grouped descriptors do not span original signed generation")
    }
    receipt,err:=hex.DecodeString(g.ReceiptSHA256)
    if err!=nil||len(receipt)!=32{return empty,errors.New("FI C1 FULL: invalid receipt digest")}
    var role,database string
    var standby bool
    if err=conn.QueryRow(ctx,"SELECT current_user,current_database(),pg_is_in_recovery()").
        Scan(&role,&database,&standby);err!=nil{return empty,err}
    if role!="fi_ingest"||database!="fi"||standby{
        return empty,errors.New("FI C1 FULL: prohibited database identity or recovery state")
    }
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly})
    if err!=nil{return empty,err}
    defer tx.Rollback(context.Background())
    shadow:=privateProjectionTx{Tx:tx}
    shadowID,ok,err:=lookupRecordedGeneration(ctx,shadow,
        ds[0].SourceID,ds[0].GenerationID,g.Receipt.TransferSHA256,g.ReceiptSHA256)
    if err!=nil{return empty,err}
    if !ok||shadowID<=0{return empty,errors.New("FI C1 FULL: signed private shadow generation absent")}
    var typedCount,totalRows,totalBytes int64
    err=tx.QueryRow(ctx,`SELECT count(*),coalesce(sum(committed_records),0),coalesce(sum(committed_bytes),0)
FROM fi_recovery.typed_window WHERE receipt_sha256=$1`,receipt).
        Scan(&typedCount,&totalRows,&totalBytes)
    if err!=nil{return empty,err}
    if typedCount!=int64(len(ds)) || totalRows!=int64(g.Receipt.RecordCount) ||
        totalBytes!=int64(g.Receipt.DataBytes){
        return empty,fmt.Errorf("FI C1 FULL: typed marker totals disagree with receipt windows=%d/%d records=%d/%d bytes=%d/%d",
            typedCount,len(ds),totalRows,g.Receipt.RecordCount,totalBytes,g.Receipt.DataBytes)
    }
    var expectedBatch int
    var expectedRows,sumGroupBytes uint64
    for i,d:=range ds {
        if d.StartBatch!=expectedBatch || d.StartRecord!=expectedRows ||
            d.EndBatch<=d.StartBatch||d.EndRecord<=d.StartRecord ||
            d.EndBatch>len(g.Batches)||d.ReceiptSHA256!=g.ReceiptSHA256 ||
            d.TransferSHA256!=g.Receipt.TransferSHA256 ||
            d.SourceID!=g.Receipt.Descriptor.SourceID ||
            d.GenerationID!=g.Receipt.Descriptor.GenerationID{
            return empty,fmt.Errorf("FI C1 FULL: grouped receipt continuity failure at group %d",i)
        }
        if i>0 && d.PreviousDigestSHA256!=ds[i-1].DigestSHA256 {
            return empty,fmt.Errorf("FI C1 FULL: digest chain broken at group %d",i)
        }
        want,err:=hex.DecodeString(d.DigestSHA256)
        if err!=nil||len(want)!=32{return empty,errors.New("FI C1 FULL: invalid marker digest")}
        var got []byte
        var recordedShadow,startBatch,endBatch int64
        var rows,bytes int64
        var version string
        err=tx.QueryRow(ctx,`SELECT descriptor_sha256,shadow_generation_id,
 start_batch,end_batch,committed_records,committed_bytes,ingest_version
 FROM fi_recovery.typed_window WHERE receipt_sha256=$1 AND window_index=$2`,
            receipt,i).Scan(&got,&recordedShadow,&startBatch,&endBatch,&rows,&bytes,&version)
        if err!=nil{return empty,fmt.Errorf("FI C1 FULL: missing durable typed marker %d: %w",i,err)}
        if len(got)!=32 || subtle.ConstantTimeCompare(want,got)!=1 ||
            recordedShadow!=shadowID||startBatch!=int64(d.StartBatch)||
            endBatch!=int64(d.EndBatch) ||
            rows!=int64(d.EndRecord-d.StartRecord) ||
            bytes!=int64(d.DataBytes) || version!=IngestVersion{
            return empty,fmt.Errorf("FI C1 FULL: typed marker %d mismatches signed group",i)
        }
        expectedBatch=d.EndBatch
        expectedRows=d.EndRecord
        sumGroupBytes+=d.DataBytes
    }
    if expectedBatch!=len(g.Batches)||expectedRows!=g.Receipt.RecordCount||
        sumGroupBytes!=g.Receipt.DataBytes{
        return empty,errors.New("FI C1 FULL: grouped totals do not equal signed receipt")
    }
    var sourceBatches,sourceRecords int64
    err=tx.QueryRow(ctx,`SELECT
 (SELECT count(*) FROM fi_recovery_projection.source_batch WHERE recorded_generation_id=$1),
 (SELECT count(*) FROM fi_recovery_projection.source_record AS sr
  JOIN fi_recovery_projection.source_batch AS sb ON sb.source_batch_id=sr.source_batch_id
  WHERE sb.recorded_generation_id=$1)`,shadowID).
        Scan(&sourceBatches,&sourceRecords)
    if err!=nil{return empty,err}
    if sourceBatches!=int64(len(g.Batches))||sourceRecords!=int64(g.Receipt.RecordCount){
        return empty,fmt.Errorf("FI C1 FULL: private signed source incomplete batches=%d/%d records=%d/%d",
            sourceBatches,len(g.Batches),sourceRecords,g.Receipt.RecordCount)
    }
    var published,accepted,sourceMarkers,artifactMarkers int64
    err=tx.QueryRow(ctx,`SELECT
 (SELECT count(*) FROM fi.recorded_generation),
 (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'),
 (SELECT count(*) FROM fi_recovery.source_window WHERE receipt_sha256=$1),
 (SELECT count(*) FROM fi_recovery.verified_artifact_window WHERE receipt_sha256=$1)`,receipt).
        Scan(&published,&accepted,&sourceMarkers,&artifactMarkers)
    if err!=nil{return empty,err}
    if published!=0||accepted!=0||sourceMarkers!=1||artifactMarkers!=1{
        return empty,fmt.Errorf("FI C1 FULL: clone-only publication or original seed marker protection failed pub=%d accepted=%d source=%d artifacts=%d",
            published,accepted,sourceMarkers,artifactMarkers)
    }
    fmt.Printf("FI C1 FULL GROUPED RELATIONAL PROOF PASS windows=%d signed_batches=%d records=%d bytes=%d typed_markers=%d source_parent_rows=%d authoritative=0 accepted=0 artifact_source_markers=seed_only proof=private_clone_only\n",
        len(ds),len(g.Batches),g.Receipt.RecordCount,g.Receipt.DataBytes,
        typedCount,sourceRecords)
    return BacklogGenerationVerification{
        SourceID:ds[0].SourceID,GenerationID:ds[0].GenerationID,
        ReceiptSHA256:g.ReceiptSHA256,ShadowGenerationID:shadowID,
        Windows:len(ds),Records:g.Receipt.RecordCount,DataBytes:g.Receipt.DataBytes,
    },nil
}
