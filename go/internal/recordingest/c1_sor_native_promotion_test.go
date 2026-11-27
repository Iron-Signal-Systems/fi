//go:build fi_c1_sor_dev
package recordingest

import (
    "context"
    "testing"
    "strings"
)

func TestC1NativePromotionRequiresVerifiedBPlan(t *testing.T){
    plan:=c1NativeBTestPlan()
    g,err:=c1NativePromotionGeneration(plan)
    if err!=nil{t.Fatal(err)}
    if g.Receipt.Descriptor.SourceID!=plan.Start.SourceID||
        g.Receipt.Descriptor.GenerationID!=plan.Start.GenerationID||
        g.ReceiptSHA256!=plan.Start.ReceiptSHA256||
        g.Receipt.RecordCount!=3||g.Receipt.DataBytes!=120||
        g.Receipt.BatchCount!=2{
        t.Fatal("C1 canonical remap has incomplete original signed private-generation metadata")
    }
    plan.Batches[1].Manifest.DataSHA256="not-signed"
    if _,err=c1NativePromotionGeneration(plan);err==nil{
        t.Fatal("C1 canonical promotion accepted malformed original batch manifest SHA")
    }
}
func TestC1NativePromotionRejectsMissingIndependentProofOrPublisher(t *testing.T){
    plan:=c1NativeBTestPlan()
    if _,err:=PromoteC1VerifiedToPopulatedSoR(context.Background(),
        nil,nil,plan,c1NativeBCustodyConfig{},"attempt-1");err==nil{
        t.Fatal("C1 allowed canonical publication without two SQL connections")
    }
    plan.Start.ReceiptSHA256=strings.Repeat("x",64)
    if _,err:=c1NativePromotionGeneration(plan);err==nil{
        t.Fatal("C1 allowed canonical promotion using noncanonical receipt")
    }
}
