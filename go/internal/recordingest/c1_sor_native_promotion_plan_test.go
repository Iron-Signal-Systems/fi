//go:build fi_c1_sor_dev
package recordingest

import (
    "testing"
    "strings"
)

func TestC1NativePromotionFullSignedGroupsBuiltWithoutSeedOnlyProof(t *testing.T){
    old:=c1NativeBTestPlan()
    p,err:=c1BuildFullNativePromotionPlan(old.Start.SourceID,
        old.Start.GenerationID,old.Start.ReceiptSHA256,old.Transfer,
        old.SQLIDs,old.Batches)
    if err!=nil{t.Fatal(err)}
    if p.Start.StartBatchIndex!=0||p.Start.ExpectedRecords!=3||
        p.Descriptors[0].EndBatch!=0||
        p.Descriptors[len(p.Descriptors)-1].EndRecord!=3{
        t.Fatal("C1 canonical plan failed to reconstruct FULL signed generation, including seed")
    }
    p.Batches[1].Manifest.RecordCount=100
    if err=c1ValidateNativeBPlan(p);err==nil{
        t.Fatal("native C1 full proof accepted modified signed source count")
    }
}
func TestC1NativePromotionRejectsOutOfOrderAndMalformedReceipts(t *testing.T){
    p:=c1NativeBTestPlan()
    if _,err:=c1BuildFullNativePromotionPlan("s","g",
        strings.Repeat("z",64),p.Transfer,p.SQLIDs,p.Batches);err==nil{
        t.Fatal("noncanonical signed receipt accepted")
    }
    p.Batches[1].BatchID=p.Batches[0].BatchID
    if _,err:=c1BuildFullNativePromotionPlan("s","g",
        p.Start.ReceiptSHA256,p.Transfer,p.SQLIDs,p.Batches);err==nil{
        t.Fatal("duplicate signed source batch accepted")
    }
}
