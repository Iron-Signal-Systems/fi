// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "path/filepath"
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func writeScopedTestSpool(t *testing.T, projections []ScopedProjection) []spool.FinalizedBatch{
    t.Helper()
    dir:=filepath.Join(t.TempDir(),"spool")
    writer,err:=spool.NewWriter(dir,spool.DefaultBatchSize,spool.CollectorIdentity{
        ExecutablePath:"test-fi-collector",ExecutableSHA256:strings.Repeat("a",64),
    })
    if err!=nil{t.Fatal(err)}
    for _,p:=range projections{
        if err:=writer.Append("USNScopedCapture",p.GovernedScopeID,p);err!=nil{t.Fatal(err)}
    }
    if err:=writer.Close();err!=nil{t.Fatal(err)}
    return writer.FinalizedBatches()
}
func onePublishedScopedSource(t *testing.T) ScopedProjection{
    t.Helper()
    seg:=exampleScopedSegment(t)
    selection:=ScopeSelection{Total:len(seg.Batch.Records),Unresolved:len(seg.Batch.Records)}
    for _,c:=range seg.Batch.Records {
        selection.Included=append(selection.Included,ScopedChange{Source:c,Class:ScopeUnresolved})
    }
    p,err:=BuildScopedProjection(seg,"root-test",scopeTestIdentity("1"),selection)
    if err!=nil{t.Fatal(err)}
    return p
}
func TestVerifiedScopedPublicationRequiresExactSourceAndRoot(t *testing.T){
    p:=onePublishedScopedSource(t)
    batches:=writeScopedTestSpool(t,[]ScopedProjection{p})
    proof,err:=VerifyScopedPublication([]ScopedProjection{p},batches)
    if err!=nil||!strings.HasPrefix(proof.Receipt(),"verified-fi-usn-scoped-spool/1:"){
        t.Fatalf("failed verified source publication: %q %v",proof,err)
    }
    forged:=p
    forged.CapturedAt="2030-01-01T00:00:00Z"
    if _,err:=VerifyScopedPublication([]ScopedProjection{forged},batches);err==nil{
        t.Fatal("altered expected source was accepted")
    }
}
func TestVerifiedScopedPublicationDoesNotAcceptMissingOrDuplicateRoot(t *testing.T){
    p:=onePublishedScopedSource(t)
    other:=p
    other.GovernedScopeID="root-second"
    other.RootIdentity=records.NTFSObjectIdentity{MethodVersion:"ntfs-file-id/1",FileReferenceNumber:"77",SequenceNumber:"1"}
    batches:=writeScopedTestSpool(t,[]ScopedProjection{p})
    if _,err:=VerifyScopedPublication([]ScopedProjection{p,other},batches);err==nil{
        t.Fatal("processed cursor could advance with one missing governed root")
    }
    dup:=writeScopedTestSpool(t,[]ScopedProjection{p,p})
    if _,err:=VerifyScopedPublication([]ScopedProjection{p},dup);err==nil{
        t.Fatal("duplicate governed source was accepted")
    }
}
