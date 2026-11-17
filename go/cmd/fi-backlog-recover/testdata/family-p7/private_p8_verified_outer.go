// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// P8 disposable C220 clone only: reuse the same-process verified artifact
// checkpoint handed directly from the cached recovery loop. Never infer
// verification from an existing directory or from an old SQL checkpoint.
package recordingest

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "path/filepath"
)

type privateP8OuterEvidenceKey struct{}
type privateP8OuterEvidence struct {
    privateRoot string
    index int
    descriptor BacklogCheckpointDescriptor
}

// This constructor MUST be called only after BOTH MaterializeBacklogWindow
// and RecordVerifiedBacklogArtifactWindow have returned success in the
// current process. An old persisted marker is never sufficient by itself.
// The original P7 stage remains fully verifying if this evidence is absent.
func privateP8WithVerifiedOuterArtifact(ctx context.Context,root string,
    d BacklogCheckpointDescriptor,index int)(context.Context,error){
    if ctx==nil || !privateP7FiveWriterSelected() || root=="" ||
        !filepath.IsAbs(root) || filepath.Clean(root)!=root ||
        index<1 || d.StartBatch<0 || d.EndBatch<=d.StartBatch ||
        d.ReceiptSHA256=="" || d.DigestSHA256=="" {
        return nil,errors.New("FI P8: same-process verified outer artifact is not eligible")
    }
    return context.WithValue(ctx,privateP8OuterEvidenceKey{},
        privateP8OuterEvidence{privateRoot:root,index:index,descriptor:d}),nil
}

func privateP8OuterEvidenceMatches(ctx context.Context,root string,
    d BacklogCheckpointDescriptor,index int)bool{
    if ctx==nil || !privateP7FiveWriterSelected() ||
        index<1 || root=="" {return false}
    proof,ok:=ctx.Value(privateP8OuterEvidenceKey{}).(privateP8OuterEvidence)
    return ok && proof.index==index && proof.privateRoot==root &&
        proof.descriptor==d
}

// A metadata+manifest-only check here is deliberately NOT a substitute
// for SHA verification: the outer materializer already hashed the exact
// bytes, the outer artifact checkpoint independently rehashed them, and
// StageVerifiedBacklogSourceWindow scans every signed data byte/record
// against its original manifest before durable source publication.
// The typed reader independently checks SHA-256 once more after this stage.
func privateP8ReusableStage(ctx context.Context,g *PreparedGeneration,
    limits BacklogWindowLimits,index int,root string,
    d BacklogCheckpointDescriptor)(string,bool,error){
    if !privateP8OuterEvidenceMatches(ctx,root,d,index) {
        // A forged/mismatched proof is a STOP, not permission to downgrade
        // to a different source stage accidentally.
        if ctx!=nil && ctx.Value(privateP8OuterEvidenceKey{})!=nil {
            return "",false,errors.New("FI P8: source evidence identity mismatch")
        }
        return "",false,nil
    }
    if g==nil || index>=len(g.Batches) && d.EndBatch>len(g.Batches) ||
        d.EndBatch>len(g.Batches) {
        return "",false,errors.New("FI P8: source generation batch range invalid")
    }
    ds,err:=DescribeBacklogWindows(g,limits)
    if err!=nil || index>=len(ds) || ds[index]!=d {
        return "",false,errors.New("FI P8: signed window descriptor changed")
    }
    dir:=filepath.Join(root,"receipt-"+d.ReceiptSHA256,
        fmt.Sprintf("window-%08d",index))
    if err:=verifyPrivateBacklogRoot(root);err!=nil{return "",false,err}
    if err:=verifyPrivateBacklogRoot(filepath.Dir(dir));err!=nil{return "",false,err}
    if err:=verifyPrivateBacklogRoot(dir);err!=nil{return "",false,err}
    descriptor,err:=readBacklogStageFile(filepath.Join(dir,"descriptor.json"),16<<10)
    if err!=nil{return "",false,err}
    var decoded BacklogCheckpointDescriptor
    if err:=json.Unmarshal(descriptor,&decoded);err!=nil{return "",false,err}
    if decoded!=d{return "",false,errors.New("FI P8: signed descriptor file mismatch")}
    for i:=d.StartBatch;i<d.EndBatch;i++{
        if err:=ctx.Err();err!=nil{return "",false,err}
        b:=g.Batches[i]
        manifest,err:=readBacklogStageFile(filepath.Join(dir,
            fmt.Sprintf("batch-%08d.manifest",i)),1<<20)
        if err!=nil{return "",false,err}
        digest:=sha256.Sum256(manifest)
        if hex.EncodeToString(digest[:])!=b.ManifestSHA256 {
            return "",false,fmt.Errorf("FI P8: manifest hash mismatch batch=%d",i)
        }
        path:=filepath.Join(dir,fmt.Sprintf("batch-%08d.data",i))
        info,err:=os.Lstat(path)
        if err!=nil{return "",false,err}
        if !info.Mode().IsRegular() || info.Mode().Perm()!=0600 ||
            info.Mode()&os.ModeSymlink!=0 ||
            info.Size()!=b.Manifest.DataBytes {
            return "",false,fmt.Errorf("FI P8: staged data metadata changed batch=%d",i)
        }
    }
    return dir,true,nil
}
