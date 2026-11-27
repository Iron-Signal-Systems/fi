//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "errors"
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)

// Unit tests do not touch SQL or construct a fake successful publisher.
// They prove only that final independent B completion is required before
// a genuine fi-sor worker can issue the verified Drain ACK.
func TestC1SoRFinalProofRequiresCommittedDrainAndVerifierB(t *testing.T){
    frame:=c1handoff.Frame{Kind:c1handoff.Drain,
        SourceID:"iss-fs-22a.iss.local",GenerationID:"signed-1",
        ReceiptSHA256:strings.Repeat("a",64),Sequence:7,
    }
    s:=&C1SoRService{}
    if proof,err:=s.FinalProof(context.Background(),frame);err==nil||proof!=c1handoff.FinalNone{
        t.Fatalf("empty SoR claimed independent B proof: %d %v",proof,err)
    }
    s.session=&c1SoRCommitHandler{sourceID:frame.SourceID,
        generationID:frame.GenerationID,receipt:frame.ReceiptSHA256,drained:true}
    s.pool=&privateC1FiveSQL{}
    s.verifier=&c1SoRNativeB{}
    if proof,err:=s.FinalProof(context.Background(),frame);err==nil||proof!=c1handoff.FinalNone{
        t.Fatalf("missing B completion claimed verified: %d %v",proof,err)
    }
    s.independentlyVerified=true
    s.canonicalReadback=func(_ context.Context,dsn,source,generation,receipt string)(
        c1handoff.FinalStatus,error,
    ){
        if source!=frame.SourceID||generation!=frame.GenerationID||
            receipt!=frame.ReceiptSHA256{
            return c1handoff.FinalNone,errors.New("wrong original generation")
        }
        return c1handoff.FinalVerified,nil
    }
    if proof,err:=s.FinalProof(context.Background(),frame);err!=nil||proof!=c1handoff.FinalVerified{
        t.Fatalf("completed independent B proof lost: %d %v",proof,err)
    }
    if proof,err:=s.FinalProof(context.Background(),c1handoff.Frame{
        Kind:c1handoff.Seal,SourceID:frame.SourceID,GenerationID:frame.GenerationID,
        ReceiptSHA256:frame.ReceiptSHA256,Sequence:8,SealedGroup:1,
    });err==nil||proof!=c1handoff.FinalNone{
        t.Fatalf("non-Drain claimed final proof: %d %v",proof,err)
    }
    frame.GenerationID="another-generation"
    if proof,err:=s.FinalProof(context.Background(),frame);err==nil||proof!=c1handoff.FinalNone{
        t.Fatalf("foreign generation claimed final B proof: %d %v",proof,err)
    }
    frame.GenerationID=s.session.generationID
    s.failed=errors.New("injected SQL failure")
    if proof,err:=s.FinalProof(context.Background(),frame);err==nil||proof!=c1handoff.FinalNone{
        t.Fatalf("failed SQL session claimed final B proof: %d %v",proof,err)
    }
}
