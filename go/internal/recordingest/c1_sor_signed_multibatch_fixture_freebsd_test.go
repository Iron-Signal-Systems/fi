//go:build freebsd && fi_c1_sor_dev && fi_c1_schema_pg_integration

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// This native FreeBSD-only fixture uses FI's REAL spool writer (2 records per
// batch), generation signing, receiver custody, immutable recorded receipt
// and READY material. Five distinct signed records form THREE true source
// batches (2+2+1). No synthetic SQL batch/receipt IDs are manufactured.
package recordingest

import (
    "bytes"
    "context"
    "crypto/rand"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "os"
    "path/filepath"
    "time"

    "github.com/Iron-Signal-Systems/fi/go/internal/generationrecorder"
    "github.com/Iron-Signal-Systems/fi/go/internal/spool"
    "github.com/Iron-Signal-Systems/fi/go/internal/transportgeneration"
    "github.com/Iron-Signal-Systems/fi/go/internal/transportreceiver"
    "testing"
)

func c1WriteReceivedThreeBatchGeneration(t *testing.T,root,source string)m1SignedSource {
    t.Helper()
    trust,signer,certificate:=m1MakeSignedTrust(t,source)
    frozen:=filepath.Join(root,source,"frozen")
    sealed:=filepath.Join(root,source,"sealed")
    for _,path:=range []string{frozen,sealed}{
        if err:=os.MkdirAll(path,0700);err!=nil{t.Fatal(err)}
    }
    collector:=spool.CollectorIdentity{
        ExecutablePath:`C:\Program Files\FI\fi.exe`,
        ExecutableSHA256:"1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a"+
            "1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a",
    }
    writer,err:=spool.NewWriter(frozen,2,collector)
    if err!=nil{t.Fatal(err)}
    for i:=0;i<5;i++ {
        payload:=json.RawMessage(fmt.Sprintf(
            `{"source":"C1-Three-Real-Batches","error":"signed-ordinal-%d"}`,i))
        if err=writer.Append("SupportingSourceCollectionError",
            "m1-"+source,payload);err!=nil{t.Fatalf("C1 real batch writer append %d: %v",i,err)}
    }
    if err=writer.Close();err!=nil{t.Fatal(err)}
    batches:=writer.FinalizedBatches()
    if len(batches)!=3||batches[0].Manifest.RecordCount!=2||
        batches[1].Manifest.RecordCount!=2||batches[2].Manifest.RecordCount!=1{
        t.Fatalf("C1 genuine three-batch fixture partition changed: %+v",batches)
    }
    // The signing/receiving steps below are the same production objects
    // as the older single-batch M1 test, not SQL metadata re-creations.
    var nonce [8]byte
    if _,err=rand.Read(nonce[:]);err!=nil{t.Fatal(err)}
    generationID:=time.Now().UTC().Format("20060102T150405.000000000Z")+
        "-"+hex.EncodeToString(nonce[:])
    published,err:=transportgeneration.CreateSealedGeneration(context.Background(),
        transportgeneration.CreateConfig{
            BatchSigner:signer,BatchSigningCertificate:certificate,
            FrozenDir:frozen,GenerationID:generationID,
            SealedRoot:sealed,SourceID:source,MaxEncodedBytes:64<<20,
        })
    if err!=nil{t.Fatal(err)}
    offer,err:=transportgeneration.OfferFromPublished(published)
    if err!=nil{t.Fatal(err)}
    var wire bytes.Buffer
    if err=transportgeneration.WriteOffer(&wire,offer);err!=nil{t.Fatal(err)}
    if _,err=transportgeneration.WritePublishedGeneration(&wire,published);err!=nil{t.Fatal(err)}
    cfg:=transportreceiver.GenerationReceiveConfig{
        Custody:transportgeneration.CustodyConfig{
            RootDir:filepath.Join(root,"custody"),
            Receive:transportgeneration.ReceiveConfig{
                BatchCRL:trust.BatchCRL,BatchIssuer:trust.BatchIssuer,
                CurrentTime:time.Now().UTC(),MaxCanonicalBytes:64<<20,
                MaxEncodedBytes:64<<20,Root:trust.Root,Source:trust.Source,
            },
        },
        ReadyRoot:filepath.Join(root,"ready"),
        Recorder:generationrecorder.DurableConfig{
            RootDir:filepath.Join(root,"recorded"),SourceNamespaces:true,
            Semantic:generationrecorder.Config{MaxManifestBytes:1<<20},
        },
    }
    var reply bytes.Buffer
    recorded,err:=transportreceiver.ReceiveGenerationAndAcknowledge(&wire,&reply,cfg)
    if err!=nil{t.Fatal(err)}
    if recorded.Recorder.Disposition!=generationrecorder.RecordedDispositionNew||
        recorded.ReadyWarning!=""{
        t.Fatalf("C1 three-batch receiver did not record/READY immutably: %+v",recorded)
    }
    decision,err:=transportgeneration.ReadDecision(&reply)
    if err!=nil{t.Fatal(err)}
    ack,err:=transportgeneration.ReadAcknowledgement(&reply)
    if err!=nil{t.Fatal(err)}
    if !decision.Accepted||ack.Outcome!=transportgeneration.AcknowledgementOutcomeRecorded{
        t.Fatal("C1 three original signed batches not acknowledged by receiver")
    }
    return m1SignedSource{
        GenerationID:generationID,SourceID:source,
        ReceiptPath:recorded.Recorder.ReceiptPath,Trust:trust,
    }
}

