//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)

func TestC1PendingRemapOnlyAcceptsGovernedSQLSource(t *testing.T){
    for _,schema:=range []string{"fi","pg_catalog","public",
        "fi_c1_pending; DROP SCHEMA fi","fi_recovery"}{
        if got,err:=sorPromotionSourceSchema(schema);err==nil{
            t.Fatalf("C1 remapper allowed untrusted namespace %q -> %q",schema,got)
        }
    }
    if got,err:=sorPromotionSourceSchema();err!=nil||got!=privateProjectionSchema{
        t.Fatalf("old isolated publisher changed: %q %v",got,err)
    }
    if got,err:=sorPromotionSourceSchema(c1GovernedPendingSchema);err!=nil||got!=c1GovernedPendingSchema{
        t.Fatalf("pending relational mapping unavailable: %q %v",got,err)
    }
    if _,err:=sorPromotionSourceSchema(privateProjectionSchema,c1GovernedPendingSchema);err==nil{
        t.Fatal("C1 publisher accepted multiple source schemas")
    }
}

func TestC1PendingRemapPreservesTypedFKIdentityMaps(t *testing.T){
    cols:=[]bootstrapColumn{
        {name:"source_record_id",notNull:true},
        {name:"source_batch_id",notNull:true},
        {name:"record_kind",notNull:true},
    }
    query,err:=compileSoRRemapSelect("source_record",cols,c1GovernedPendingSchema)
    if err!=nil{t.Fatal(err)}
    for _,value:=range []string{
        "INSERT INTO \"fi\".\"source_record\"",
        "FROM \"fi_c1_pending\".\"source_record\"",
        "fi_promote_map_source_batch",
        "fi_promote_map_source_record",
    }{
        if !strings.Contains(query,value){
            t.Fatalf("C1 pending remapper omitted %q in %q",value,query)
        }
    }
    if strings.Contains(query,privateProjectionSchema)||
        strings.Contains(query,"fi_recovery.")||
        strings.Contains(query,"INSERT INTO \"fi_c1_pending\""){
        t.Fatalf("C1 pending remapper references unauthorized target: %s",query)
    }
    old,err:=compileSoRRemapSelect("source_record",cols)
    if err!=nil||!strings.Contains(old,"FROM \"fi_recovery_projection\".\"source_record\""){
        t.Fatalf("isolated remapper changed: %q %v",old,err)
    }
}

func TestC1PendingFinalProofRefusesConcurrentPublisher(t *testing.T){
    f:=c1handoff.Frame{
        Kind:c1handoff.Drain,Sequence:7,
        SourceID:"signed-source",GenerationID:"signed-generation",
        ReceiptSHA256:strings.Repeat("a",64),
    }
    s:=&C1SoRService{
        independentlyVerified:true,publishing:true,
        session:&c1SoRCommitHandler{
            drained:true,sourceID:f.SourceID,generationID:f.GenerationID,
            receipt:f.ReceiptSHA256,
        },
        pool:&privateC1FiveSQL{},verifier:&c1SoRNativeB{},
    }
    if got,err:=s.FinalProof(context.Background(),f);err==nil||got!=c1handoff.FinalNone{
        t.Fatalf("concurrent C1 canonical publication falsely accepted: %v %v",got,err)
    }
}
