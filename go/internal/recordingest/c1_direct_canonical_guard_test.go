//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "strings"
    "testing"
)

func TestC1DirectCanonicalStartRejectsExistingAcceptedReplay(t *testing.T) {
    signed:=C1DirectCanonicalOriginal{
        SourceID:"iss-fs-22a.iss.local",
        GenerationID:"20261030T000032.061323100Z-3e38b2210771462c",
        ReceiptSHA256:"29891703eea7bef6e21b84374c49193a9b1d58666665d418267e418e3414c7ed",
        TransferSHA256:"ce170d4e7ce023cde3327938b7fc345201c4692aed50160584dbc1c21d42e8e5",
        SignedRecords:15140785,SignedBatches:8399,
    }
    exact:=C1DirectCanonicalEvidence{
        ExistingGenerations:1,ExistingRecords:15140785,ExistingBatches:8399,
        ExistingReceiptSHA256:signed.ReceiptSHA256,ExistingTransferSHA256:signed.TransferSHA256,
        AcceptedEvents:1,MatchingAcceptedEvents:1,
    }
    tests:=[]struct {
        name string
        signed C1DirectCanonicalOriginal
        evidence C1DirectCanonicalEvidence
        want C1DirectCanonicalStartStatus
        fail bool
    }{
        {"new original generation",signed,C1DirectCanonicalEvidence{},C1DirectCanonicalNew,false},
        {"same signed generation already Accepted",signed,exact,C1DirectCanonicalAlreadyAccepted,false},
        {"existing Accepted but incorrect receipt",signed,func()C1DirectCanonicalEvidence{a:=exact;a.ExistingReceiptSHA256=strings.Repeat("a",64);return a}(),C1DirectCanonicalBlocked,true},
        {"existing Accepted but incorrect transfer",signed,func()C1DirectCanonicalEvidence{a:=exact;a.ExistingTransferSHA256=strings.Repeat("a",64);return a}(),C1DirectCanonicalBlocked,true},
        {"existing Accepted but wrong row count",signed,func()C1DirectCanonicalEvidence{a:=exact;a.ExistingRecords--;return a}(),C1DirectCanonicalBlocked,true},
        {"existing Accepted but wrong batch count",signed,func()C1DirectCanonicalEvidence{a:=exact;a.ExistingBatches--;return a}(),C1DirectCanonicalBlocked,true},
        {"incomplete canonical exists, no Accepted",signed,func()C1DirectCanonicalEvidence{a:=exact;a.AcceptedEvents=0;a.MatchingAcceptedEvents=0;return a}(),C1DirectCanonicalBlocked,true},
        {"pending state blocks new",signed,C1DirectCanonicalEvidence{PendingGenerations:1},C1DirectCanonicalBlocked,true},
        {"pending state blocks accepted",signed,func()C1DirectCanonicalEvidence{a:=exact;a.PendingGenerations=1;return a}(),C1DirectCanonicalBlocked,true},
        {"accepted journal without canonical generation",signed,C1DirectCanonicalEvidence{AcceptedEvents:1,MatchingAcceptedEvents:1},C1DirectCanonicalBlocked,true},
        {"accepted journal mismatched commitment",signed,func()C1DirectCanonicalEvidence{a:=exact;a.MatchingAcceptedEvents=0;return a}(),C1DirectCanonicalBlocked,true},
        {"duplicate Accepted events",signed,func()C1DirectCanonicalEvidence{a:=exact;a.AcceptedEvents=2;a.MatchingAcceptedEvents=2;return a}(),C1DirectCanonicalBlocked,true},
        {"duplicate canonical generations",signed,func()C1DirectCanonicalEvidence{a:=exact;a.ExistingGenerations=2;return a}(),C1DirectCanonicalBlocked,true},
        {"invalid original signed receipt",func()C1DirectCanonicalOriginal{a:=signed;a.ReceiptSHA256="invalid";return a}(),C1DirectCanonicalEvidence{},C1DirectCanonicalBlocked,true},
        {"invalid original transfer hash",func()C1DirectCanonicalOriginal{a:=signed;a.TransferSHA256="invalid";return a}(),C1DirectCanonicalEvidence{},C1DirectCanonicalBlocked,true},
        {"zero signed batch count",func()C1DirectCanonicalOriginal{a:=signed;a.SignedBatches=0;return a}(),C1DirectCanonicalEvidence{},C1DirectCanonicalBlocked,true},
    }
    for _,tt:=range tests{
        t.Run(tt.name,func(t *testing.T){
            got,err:=EvaluateC1DirectCanonicalStart(tt.signed,tt.evidence)
            if got!=tt.want || (err!=nil)!=tt.fail{
                t.Fatalf("got status=%d err=%v want=%d fail=%t",got,err,tt.want,tt.fail)
            }
            if got==C1DirectCanonicalAlreadyAccepted&&err==nil {
                // Previously accepted is a NO-WRITE state, not ingestion authorization.
                if got==C1DirectCanonicalNew{t.Fatal("already Accepted cannot authorize new insert")}
            }
        })
    }
}
