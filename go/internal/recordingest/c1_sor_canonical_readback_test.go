//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "bytes"
    "encoding/hex"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)

func TestC1CanonicalAcceptedRequiresExactOriginalReceiptAndUniqueJournal(t *testing.T){
    receipt:=bytes.Repeat([]byte{0xa3},32)
    transfer:=bytes.Repeat([]byte{0x51},32)
    signed:=hex.EncodeToString(receipt)
    accepted:=c1CanonicalEvidence{generationExists:true,
        recordedReceipt:receipt,recordedTransfer:transfer,
        records:500000,batches:10,acceptedEvents:1,matchingAcceptedEvents:1}
    status,err:=c1CanonicalStatusFromEvidence(signed,accepted)
    if err!=nil||status!=c1handoff.FinalAccepted{
        t.Fatalf("exact canonical source and Accepted journal rejected: %d %v",status,err)
    }
    incomplete:=c1CanonicalEvidence{}
    status,err=c1CanonicalStatusFromEvidence(signed,incomplete)
    if err!=nil||status!=c1handoff.FinalVerified{
        t.Fatalf("independent B SQL stage misclassified: %d %v",status,err)
    }
    cases:=map[string]func(*c1CanonicalEvidence){
        "wrong-signed-receipt":func(e *c1CanonicalEvidence){
            e.recordedReceipt=bytes.Repeat([]byte{0xff},32)
        },
        "missing-accepted-journal":func(e *c1CanonicalEvidence){
            e.acceptedEvents=0;e.matchingAcceptedEvents=0
        },
        "duplicate-accepted-events":func(e *c1CanonicalEvidence){
            e.acceptedEvents=2;e.matchingAcceptedEvents=2
        },
        "conflicting-accepted-journal":func(e *c1CanonicalEvidence){
            e.acceptedEvents=1;e.matchingAcceptedEvents=0
        },
        "missing-transfer":func(e *c1CanonicalEvidence){e.recordedTransfer=nil},
        "empty-canonical":func(e *c1CanonicalEvidence){e.records=0},
        "missing-signed-batches":func(e *c1CanonicalEvidence){e.batches=0},
        "journal-without-generation":func(e *c1CanonicalEvidence){e.generationExists=false},
    }
    for name,mutate:=range cases{
        t.Run(name,func(t *testing.T){
            e:=accepted
            mutate(&e)
            got,err:=c1CanonicalStatusFromEvidence(signed,e)
            if err==nil||got!=c1handoff.FinalNone{
                t.Fatalf("failed closed on inconsistent canonical evidence: %d %v",got,err)
            }
        })
    }
    if got,err:=c1CanonicalStatusFromEvidence("invalid-digest",accepted);err==nil||got!=c1handoff.FinalNone{
        t.Fatalf("accepted invalid signed receipt digest: %d %v",got,err)
    }
}
