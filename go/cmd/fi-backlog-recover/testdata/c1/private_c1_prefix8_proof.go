// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Only a C220 disposable clone. This proves a selected two-group / near-8GiB
// *prefix* and NEVER asserts full signed-generation completion or acceptance.
package recordingest

import (
    "context"
    "crypto/subtle"
    "encoding/hex"
    "errors"
    "fmt"

    "github.com/jackc/pgx/v5"
)

func privateC1ValidateEightGiBPrefix(g *PreparedGeneration,
    ds []BacklogCheckpointDescriptor,end int)error{
    if g==nil||end!=3||len(ds)<=end||
        ds[0].EndBatch<=0||ds[0].EndRecord==0||
        ds[0].StartBatch!=0||ds[0].StartRecord!=0||
        // The last SELECTED prefix group must stop before the source ends.
        // ds[end] describes the remaining tail and may itself end at the
        // full-generation boundary; that is not a prefix completion.
        ds[end-1].EndBatch>=len(g.Batches)||
        ds[0].ReceiptSHA256!=g.ReceiptSHA256 {
        return errors.New("FI C1 8G: expected exactly two nonterminal signed groups after immutable seed")
    }
    var signedBytes uint64
    for i:=1;i<end;i++{
        a,b:=ds[i-1],ds[i]
        if b.StartBatch!=a.EndBatch||b.StartRecord!=a.EndRecord||
            b.EndBatch<=b.StartBatch||b.EndRecord<=b.StartRecord||
            b.DataBytes>4<<30||b.ReceiptSHA256!=g.ReceiptSHA256||
            b.PreviousDigestSHA256!=a.DigestSHA256{
            return fmt.Errorf("FI C1 8G: invalid signed group %d",i)
        }
        var manifestRecords,manifestBytes uint64
        for j:=b.StartBatch;j<b.EndBatch;j++{
            m:=g.Batches[j].Manifest
            if m.RecordCount<=0||m.DataBytes<=0{return errors.New("FI C1 8G: invalid signed batch")}
            manifestRecords+=uint64(m.RecordCount)
            manifestBytes+=uint64(m.DataBytes)
        }
        if manifestRecords!=b.EndRecord-b.StartRecord||manifestBytes!=b.DataBytes{
            return fmt.Errorf("FI C1 8G: signed manifest totals mismatch at group %d",i)
        }
        signedBytes+=b.DataBytes
    }
    if signedBytes<(8<<30)-(64<<20)||signedBytes>8<<30 {
        return fmt.Errorf("FI C1 8G: signed prefix data size %d is outside permitted near-8GiB range",signedBytes)
    }
    return nil
}

func privateC1VerifyEightGiBPrefix(ctx context.Context,conn *pgx.Conn,
    g *PreparedGeneration,ds []BacklogCheckpointDescriptor,end int)error{
    if ctx==nil||conn==nil{return errors.New("FI C1 8G: missing verifier connection")}
    if err:=privateC1ValidateEightGiBPrefix(g,ds,end);err!=nil{return err}
    var role,db string
    var standby bool
    if err:=conn.QueryRow(ctx,"SELECT current_user,current_database(),pg_is_in_recovery()").
        Scan(&role,&db,&standby);err!=nil{return err}
    if role!="fi_ingest"||db!="fi"||standby {
        return errors.New("FI C1 8G: prohibited database identity or recovery state")
    }
    tx,err:=conn.BeginTx(ctx,pgx.TxOptions{IsoLevel:pgx.RepeatableRead,AccessMode:pgx.ReadOnly})
    if err!=nil{return err}
    defer tx.Rollback(context.Background())
    shadow:=privateProjectionTx{Tx:tx}
    shadowID,ok,err:=lookupRecordedGeneration(ctx,shadow,
        ds[0].SourceID,ds[0].GenerationID,g.Receipt.TransferSHA256,g.ReceiptSHA256)
    if err!=nil{return err}
    if !ok||shadowID<=0{return errors.New("FI C1 8G: private signed source generation missing")}
    receipt,err:=hex.DecodeString(g.ReceiptSHA256)
    if err!=nil||len(receipt)!=32{return errors.New("FI C1 8G: invalid signed receipt digest")}
    var count,rows,bytes int64
    err=tx.QueryRow(ctx,`SELECT count(*),coalesce(sum(committed_records),0),
        coalesce(sum(committed_bytes),0)
        FROM fi_recovery.typed_window WHERE receipt_sha256=$1`,receipt).
        Scan(&count,&rows,&bytes)
    if err!=nil{return err}
    var expectedRows int64
    var expectedBytes int64
    for i:=0;i<end;i++{
        expectedRows+=int64(ds[i].EndRecord-ds[i].StartRecord)
        expectedBytes+=int64(ds[i].DataBytes)
    }
    if count!=int64(end)||rows!=expectedRows||bytes!=expectedBytes{
        return fmt.Errorf("FI C1 8G: wrong prefix typed markers or totals markers=%d/%d rows=%d/%d bytes=%d/%d",
            count,end,rows,expectedRows,bytes,expectedBytes)
    }
    for wi:=0;wi<end;wi++{
        d:=ds[wi]
        want,err:=hex.DecodeString(d.DigestSHA256)
        if err!=nil||len(want)!=32{return errors.New("FI C1 8G: invalid group digest")}
        var recorded []byte
        var recordedShadow,startBatch,endBatch,markerRows,markerBytes int64
        var version string
        err=tx.QueryRow(ctx,`SELECT descriptor_sha256,shadow_generation_id,
            start_batch,end_batch,committed_records,committed_bytes,ingest_version
            FROM fi_recovery.typed_window WHERE receipt_sha256=$1 AND window_index=$2`,
            receipt,wi).Scan(&recorded,&recordedShadow,&startBatch,&endBatch,
                &markerRows,&markerBytes,&version)
        if err!=nil{return fmt.Errorf("FI C1 8G: group %d marker missing: %w",wi,err)}
        if subtle.ConstantTimeCompare(recorded,want)!=1||
            recordedShadow!=shadowID||startBatch!=int64(d.StartBatch)||
            endBatch!=int64(d.EndBatch)||markerRows!=int64(d.EndRecord-d.StartRecord)||
            markerBytes!=int64(d.DataBytes)||version!=IngestVersion{
            return fmt.Errorf("FI C1 8G: group %d typed marker differs from signed descriptor",wi)
        }
        // The commit-ready independent worker has already proven source
        // counts and typed coverage for every requested group. This final
        // read-only prefix proof checks signed markers, original source
        // counts and absence of publication, without duplicating SQL scans.
    }
    var published,accepted,sourceMarkers,artifactMarkers,sourceRecords int64
    err=tx.QueryRow(ctx,`SELECT
        (SELECT count(*) FROM fi.recorded_generation),
        (SELECT count(*) FROM fi.ingest_journal WHERE outcome='Accepted'),
        (SELECT count(*) FROM fi_recovery.source_window WHERE receipt_sha256=$1),
        (SELECT count(*) FROM fi_recovery.verified_artifact_window WHERE receipt_sha256=$1),
        (SELECT count(*) FROM fi_recovery_projection.source_record sr
            JOIN fi_recovery_projection.source_batch sb ON sb.source_batch_id=sr.source_batch_id
            WHERE sb.recorded_generation_id=$2)`,receipt,shadowID).
        Scan(&published,&accepted,&sourceMarkers,&artifactMarkers,&sourceRecords)
    if err!=nil{return err}
    if published!=0||accepted!=0||sourceMarkers!=1||artifactMarkers!=1||sourceRecords!=expectedRows{
        return fmt.Errorf("FI C1 8G: incomplete prefix or unsafe publication source=%d/%d published=%d accepted=%d source_markers=%d artifact_markers=%d",
            sourceRecords,expectedRows,published,accepted,sourceMarkers,artifactMarkers)
    }
    fmt.Printf("FI C1 PRIVATE 8G PREFIX PROOF PASS groups=2 windows=3 source_records=%d new_records=%d source_bytes=%d signed_batches=%d full_generation=false authoritative=0 accepted=0 published=0\n",
        expectedRows,expectedRows-int64(ds[0].EndRecord),
        ds[1].DataBytes+ds[2].DataBytes,ds[2].EndBatch)
    return nil
}
