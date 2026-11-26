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

// Direct canonical is a deliberate, exact-schema runtime decision. It is
// never an arbitrary string from an original custody record or C1 frame.
func TestC1DirectCanonicalSQLNeverEnablesUnapprovedSchema(t *testing.T) {
    if _,err:=rewritePrivateProjectionStatementTo("INSERT INTO fi.source_record(record_bytes) VALUES (1)","fi");err==nil{
        t.Fatal("private projector silently authorized canonical writes")
    }
    q,err:=rewritePrivateProjectionStatementTo(
        "INSERT INTO fi.source_record(record_bytes) VALUES (1)","fi",true)
    if err!=nil||q!="INSERT INTO fi.source_record(record_bytes) VALUES (1)"{
        t.Fatalf("explicit canonical destination failed: sql=%q err=%v",q,err)
    }
    if _,err:=rewritePrivateProjectionStatementTo("INSERT INTO fi.source_record(x) VALUES (1)","public",true);err==nil{
        t.Fatal("arbitrary schema accepted")
    }
    if _,err:=rewritePrivateProjectionStatementTo("DELETE FROM fi.source_record","fi",true);err==nil{
        t.Fatal("canonical DELETE passed the immutable SQL projector gate")
    }
    if _,err:=rewritePrivateProjectionStatementTo("UPDATE fi.source_record SET record_bytes=1","fi",true);err==nil{
        t.Fatal("canonical UPDATE passed the immutable SQL projector gate")
    }
    if _,err:=rewritePrivateProjectionStatementTo("TRUNCATE fi.source_record","fi",true);err==nil{
        t.Fatal("canonical TRUNCATE passed the immutable SQL projector gate")
    }
    if _,err:=rewritePrivateProjectionStatementTo("INSERT INTO fi.source_record(x) VALUES (1); DROP SCHEMA fi","fi",true);err==nil{
        t.Fatal("multi statement injection passed canonical SQL gate")
    }
    if _,err:=(privateProjectionTx{schema:"fi"}).destinationSchema();err==nil{
        t.Fatal("canonical destination without explicit flag")
    }
    if schema,err:=(privateProjectionTx{schema:"fi",canonicalDirect:true}).destinationSchema();err!=nil||schema!="fi"{
        t.Fatalf("explicit canonical destination unavailable: %q %v",schema,err)
    }
}

// The real service routes to a B-required direct path. An incomplete source
// cannot insert metadata or invent a final Accepted event.
func TestC1DirectCanonicalDoesNotAdmitUnsignedOrUnprovedCompletion(t *testing.T) {
    s:=&C1SoRService{DirectCanonical:true}
    if _,err:=s.Bootstrap(context.Background(),c1handoff.Frame{});err==nil{
        t.Fatal("unsigned C1 START passed direct canonical admission")
    }
    f:=c1handoff.Frame{
        Kind:c1handoff.Drain,Sequence:2,SourceID:"iss-fs-22a.iss.local",
        GenerationID:"signed-test",ReceiptSHA256:strings.Repeat("a",64),
    }
    if status,err:=s.FinalProof(context.Background(),f);err==nil||status!=c1handoff.FinalNone{
        t.Fatalf("unproved direct C1 FinalProof claimed status=%d error=%v",status,err)
    }
}

func TestC1NativeBDirectCanonicalSchemaIsExplicitlyWhitelisted(t *testing.T) {
    p:=c1NativeBTestPlan()
    p.SQLSchema="fi"
    if _,err:=c1NativeBSchema(p);err!=nil{t.Fatal(err)}
    if err:=c1ValidateNativeBPlan(p);err!=nil{t.Fatal(err)}
    p.SQLSchema="other"
    if _,err:=c1NativeBSchema(p);err==nil{t.Fatal("unknown B proof schema admitted")}
}
