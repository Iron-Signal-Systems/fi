// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "strings"
    "testing"
)

func privateC1CommittedGroupFixture() []BacklogCheckpointDescriptor{
    return []BacklogCheckpointDescriptor{
        {StartBatch:0,EndBatch:10,StartRecord:0,EndRecord:50,
            ReceiptSHA256:strings.Repeat("a",64),DigestSHA256:strings.Repeat("b",64)},
        {StartBatch:10,EndBatch:12,StartRecord:50,EndRecord:53,
            ReceiptSHA256:strings.Repeat("a",64),PreviousDigestSHA256:strings.Repeat("b",64),
            DigestSHA256:strings.Repeat("c",64)},
        {StartBatch:12,EndBatch:14,StartRecord:53,EndRecord:55,
            ReceiptSHA256:strings.Repeat("a",64),PreviousDigestSHA256:strings.Repeat("c",64),
            DigestSHA256:strings.Repeat("d",64)},
        {StartBatch:14,EndBatch:16,StartRecord:55,EndRecord:58,
            ReceiptSHA256:strings.Repeat("a",64),PreviousDigestSHA256:strings.Repeat("d",64),
            DigestSHA256:strings.Repeat("e",64)},
    }
}
func privateC1CommitRows(indices ...int)[]privateP6Record{
    out:=make([]privateP6Record,0,len(indices))
    for _,index:=range indices{
        out=append(out,privateP6Record{signedBatchIndex:index})
    }
    return out
}

func TestPrivateC1CommitReadySealedAndBothSQLCommitKindsRequired(t *testing.T){
    g,err:=newPrivateC1CommitReady(privateC1CommittedGroupFixture(),1,3)
    if err!=nil{t.Fatal(err)}
    // Durable SQL work may finish BEFORE the reader seals its SHA group.
    if err=g.CommitSource(privateC1CommitRows(10,10,11));err!=nil{t.Fatal(err)}
    if err=g.CommitFamily(privateC1CommitRows(10,11,11));err!=nil{t.Fatal(err)}
    select{case <-g.notifications:t.Fatal("premature readiness before SHA seal");default:}
    if err=g.Seal(1);err!=nil{t.Fatal(err)}
    select{
    case wi:=<-g.notifications:if wi!=1{t.Fatalf("got group %d",wi)}
    default:t.Fatal("committed and SHA-sealed group was not made ready")
    }
    if err=g.Seal(2);err!=nil{t.Fatal(err)}
    if err=g.CommitSource(privateC1CommitRows(12,13));err!=nil{t.Fatal(err)}
    if err=g.CommitFamily(privateC1CommitRows(12,13));err!=nil{t.Fatal(err)}
    select{
    case wi:=<-g.notifications:if wi!=2{t.Fatalf("got group %d",wi)}
    default:t.Fatal("second committed group was not made ready")
    }
    if err=g.FinishCommitted();err!=nil{t.Fatal(err)}
    if _,ok:=<-g.notifications;ok{t.Fatal("committed ready queue did not terminate")}
}

func TestPrivateC1CommitReadyMixedFamilyHandoffAcrossGroups(t *testing.T){
    g,err:=newPrivateC1CommitReady(privateC1CommittedGroupFixture(),1,3)
    if err!=nil{t.Fatal(err)}
    if err=g.Seal(1);err!=nil{t.Fatal(err)}
    // A single SOURCE transaction and separate FAMILY transactions
    // are allowed to contain records from BOTH reporting groups.
    if err=g.CommitSource(privateC1CommitRows(10,10,11,12,13));err!=nil{t.Fatal(err)}
    if err=g.CommitFamily(privateC1CommitRows(10,12,11,13));err!=nil{t.Fatal(err)}
    select{case <-g.notifications:t.Fatal("typed group is not fully committed");default:}
    if err=g.CommitFamily(privateC1CommitRows(11));err!=nil{t.Fatal(err)}
    select{
    case wi:=<-g.notifications:if wi!=1{t.Fatalf("expected first group, got %d",wi)}
    default:t.Fatal("group one did not become ready despite complete source+typed ACKs")
    }
    // Not yet sealed: even complete SQL cannot publish readiness for group2.
    select{case <-g.notifications:t.Fatal("unsealed group two announced");default:}
    if err=g.Seal(2);err!=nil{t.Fatal(err)}
    select{
    case wi:=<-g.notifications:if wi!=2{t.Fatalf("expected second group, got %d",wi)}
    default:t.Fatal("group two not ready after verified SHA seal")
    }
    if err=g.FinishCommitted();err!=nil{t.Fatal(err)}
}

func TestPrivateC1CommitReadyRejectsMissingDurableFamilyAndOvercommit(t *testing.T){
    g,err:=newPrivateC1CommitReady(privateC1CommittedGroupFixture(),1,3)
    if err!=nil{t.Fatal(err)}
    if err=g.Seal(1);err!=nil{t.Fatal(err)}
    if err=g.Seal(2);err!=nil{t.Fatal(err)}
    if err=g.CommitSource(privateC1CommitRows(10,10,11,12,13));err!=nil{t.Fatal(err)}
    if err=g.CommitFamily(privateC1CommitRows(10,11,12,13));err!=nil{t.Fatal(err)}
    if err=g.FinishCommitted();err==nil{t.Fatal("accepted missing committed typed-family row")}
    if err=g.CommitFamily(privateC1CommitRows(11));err!=nil{t.Fatal(err)}
    if err=g.FinishCommitted();err!=nil{t.Fatal(err)}
    duplicate,err:=newPrivateC1CommitReady(privateC1CommittedGroupFixture(),1,3)
    if err!=nil{t.Fatal(err)}
    if err=duplicate.CommitSource(privateC1CommitRows(10,10,11,11));err==nil{
        t.Fatal("accepted SQL source count above signed manifest")
    }
    if err=duplicate.Seal(1);err==nil{t.Fatal("failed tracker still permits signed readiness")}
}

func TestPrivateC1CommitReadyRejectsOutOfRangeAndOutOfOrder(t *testing.T){
    g,err:=newPrivateC1CommitReady(privateC1CommittedGroupFixture(),1,3)
    if err!=nil{t.Fatal(err)}
    if err=g.Seal(2);err==nil{t.Fatal("accepted out-of-order SHA seal")}
    if err=g.CommitSource(privateC1CommitRows(999));err==nil{
        t.Fatal("accepted SQL committed row outside selected signed groups")
    }
    if err=g.Seal(1);err!=nil{t.Fatal(err)}
    if err=g.Seal(1);err==nil{t.Fatal("accepted duplicate SHA seal")}
    if err=g.FinishCommitted();err==nil{t.Fatal("accepted no committed SQL source/family rows")}
}

func TestPrivateC1CommitReadyRejectsChangedDescriptorChain(t *testing.T){
    ds:=privateC1CommittedGroupFixture()
    ds[2].PreviousDigestSHA256=strings.Repeat("f",64)
    if _,err:=newPrivateC1CommitReady(ds,1,3);err==nil{
        t.Fatal("accepted a changed signed descriptor predecessor")
    }
}
