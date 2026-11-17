// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// P8 private C220 clone experiment: reuse the exact already-committed
// artifact without patching the outer cached recovery loop.
// P7's normal source stage still verifies EVERY signed data byte before
// source marker commit, and its typed reader re-verifies batch SHA-256.
package recordingest

import (
    "context"
    "crypto/sha256"
    "crypto/subtle"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "path/filepath"

    "github.com/jackc/pgx/v5"
)

func privateP8Selected() bool {
    return os.Getenv("FI_W512_P8_REUSE")=="1" && privateP7FiveWriterSelected()
}

// The cache-resume fast path can defer physical stage creation AND omit
// the artifact SQL checkpoint before P7's typed entrypoint. Never assume
// either exists. On a missing checkpoint, copy every byte to the private
// namespace while verifying each signed batch SHA-256 as it is written.
// RecordVerifiedBacklogArtifactWindow then independently rehashes the
// durable copy and commits the exact signed receipt; the existing source
// stage hashes the original data again before its SQL marker.
// This eliminates only the additional post-copy VerifyMaterialized pass.
func privateP8FreshSignedWindow(ctx context.Context,g *PreparedGeneration,
    limits BacklogWindowLimits,index int,root string,
    d BacklogCheckpointDescriptor)(string,error){
    if !privateP8Selected()||ctx==nil||g==nil||index<1||root==""{
        return "",errors.New("FI P8: unselected private signed copy")
    }
    ds,err:=DescribeBacklogWindows(g,limits)
    if err!=nil{return "",err}
    if index>=len(ds)||ds[index]!=d{
        return "",errors.New("FI P8: signed descriptor differs from source generation")
    }
    dir,err:=materializeBacklogWindow(ctx,g,limits,index,root,false)
    if err!=nil{return "",fmt.Errorf("FI P8: verified signed copy to private artifact: %w",err)}
    want:=filepath.Join(root,"receipt-"+d.ReceiptSHA256,
        fmt.Sprintf("window-%08d",index))
    if dir!=want{return "",errors.New("FI P8: private signed window escaped its receipt namespace")}
    return dir,nil
}

// SQL evidence comes from the original full-verified artifact checkpoint
// committed by recoverBacklogVerifiedCachedWindows BEFORE P7 is entered.
// It is never inferred from a directory, cached manifest, or previously
// staged source row. The caller first verifies this control connection
// belongs to the disposable PostgreSQL clone (including its data_directory).
func privateP8CommittedArtifact(ctx context.Context, control *pgx.Conn,
    d BacklogCheckpointDescriptor,index int) error {
    if !privateP8Selected() || ctx==nil || control==nil || index<1 ||
        d.StartBatch<0 || d.EndBatch<=d.StartBatch {
        return errors.New("FI P8: verified private P7 artifact entry point required")
    }
    receipt,err:=hex.DecodeString(d.ReceiptSHA256)
    if err!=nil || len(receipt)!=32{return errors.New("FI P8: receipt SHA-256 invalid")}
    digest,err:=hex.DecodeString(d.DigestSHA256)
    if err!=nil || len(digest)!=32{return errors.New("FI P8: window descriptor SHA-256 invalid")}
    previous,err:=hex.DecodeString(d.PreviousDigestSHA256)
    if err!=nil || len(previous)!=32{return errors.New("FI P8: preceding descriptor SHA-256 invalid")}
    transfer,err:=hex.DecodeString(d.TransferSHA256)
    if err!=nil || len(transfer)!=32{return errors.New("FI P8: transfer SHA-256 invalid")}
    var gotDigest,gotPrevious,gotTransfer []byte
    var gotSource,gotGeneration string
    var fromBatch,toBatch int
    var fromRecord,toRecord,bytes int64
    err=control.QueryRow(ctx,`
SELECT descriptor_sha256,previous_digest_sha256,transfer_sha256,
       source_id,generation_id,start_batch,end_batch,
       start_record,end_record,data_bytes
FROM fi_recovery.verified_artifact_window
WHERE receipt_sha256=$1 AND window_index=$2
`,receipt,index).Scan(&gotDigest,&gotPrevious,&gotTransfer,
        &gotSource,&gotGeneration,&fromBatch,&toBatch,
        &fromRecord,&toRecord,&bytes)
    if err!=nil{return fmt.Errorf("FI P8: committed outer artifact checkpoint missing: %w",err)}
    if subtle.ConstantTimeCompare(gotDigest,digest)!=1 ||
        subtle.ConstantTimeCompare(gotPrevious,previous)!=1 ||
        subtle.ConstantTimeCompare(gotTransfer,transfer)!=1 ||
        gotSource!=d.SourceID || gotGeneration!=d.GenerationID ||
        fromBatch!=d.StartBatch || toBatch!=d.EndBatch ||
        fromRecord!=int64(d.StartRecord) || toRecord!=int64(d.EndRecord) ||
        bytes!=int64(d.DataBytes) {
        return errors.New("FI P8: committed outer artifact does not match original signed receipt")
    }
    return nil
}

// Verify the exact private namespace, descriptor, original signed manifests
// and file metadata. This is NOT the final hash check: the unchanged
// StageVerifiedBacklogSourceWindow hashes all data and SQL source rows before
// committing, then ingestSourceBatch hashes each original signed batch
// before publishing its typed marker. No skipped trust boundary remains.
func privateP8ReusableStage(ctx context.Context,g *PreparedGeneration,
    limits BacklogWindowLimits,index int,root string,
    d BacklogCheckpointDescriptor)(string,error){
    if !privateP8Selected() || ctx==nil || g==nil || root=="" ||
        !filepath.IsAbs(root) || filepath.Clean(root)!=root ||
        index<1 || d.StartBatch<0 || d.EndBatch>len(g.Batches) ||
        d.StartBatch>=d.EndBatch {
        return "",errors.New("FI P8: invalid private signed artifact namespace or selection")
    }
    ds,err:=DescribeBacklogWindows(g,limits)
    if err!=nil || index>=len(ds) || ds[index]!=d {
        return "",errors.New("FI P8: signed window descriptor changed")
    }
    dir:=filepath.Join(root,"receipt-"+d.ReceiptSHA256,
        fmt.Sprintf("window-%08d",index))
    if err:=verifyPrivateBacklogRoot(root);err!=nil{return "",err}
    if err:=verifyPrivateBacklogRoot(filepath.Dir(dir));err!=nil{return "",err}
    if err:=verifyPrivateBacklogRoot(dir);err!=nil{return "",err}
    raw,err:=readBacklogStageFile(filepath.Join(dir,"descriptor.json"),16<<10)
    if err!=nil{return "",err}
    var got BacklogCheckpointDescriptor
    if err:=json.Unmarshal(raw,&got);err!=nil{return "",err}
    if got!=d{return "",errors.New("FI P8: private stage descriptor differs from signed window")}
    for i:=d.StartBatch;i<d.EndBatch;i++{
        if err:=ctx.Err();err!=nil{return "",err}
        b:=g.Batches[i]
        manifest,err:=readBacklogStageFile(filepath.Join(dir,
            fmt.Sprintf("batch-%08d.manifest",i)),1<<20)
        if err!=nil{return "",err}
        sum:=sha256.Sum256(manifest)
        if hex.EncodeToString(sum[:])!=b.ManifestSHA256 {
            return "",fmt.Errorf("FI P8: original signed manifest SHA changed batch=%d",i)
        }
        path:=filepath.Join(dir,fmt.Sprintf("batch-%08d.data",i))
        info,err:=os.Lstat(path)
        if err!=nil{return "",err}
        if !info.Mode().IsRegular() || info.Mode().Perm()!=0600 ||
            info.Mode()&os.ModeSymlink!=0 || info.Size()!=b.Manifest.DataBytes {
            return "",fmt.Errorf("FI P8: staged signed data metadata changed batch=%d",i)
        }
    }
    return dir,nil
}
