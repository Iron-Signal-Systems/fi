// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "encoding/json"
    "errors"
    "os"
    "path/filepath"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func verifiedBootstrapActivationFixture(t *testing.T)(string,string,[]byte){
    t.Helper()
    root:=t.TempDir()
    anchor:=exampleAnchor()
    volumeScope,err:=VolumeCaptureScopeID(anchor.VolumeIdentity)
    if err!=nil{t.Fatal(err)}
    anchor.ScopeID=volumeScope
    dir:=filepath.Join(root,volumeScope)
    if err:=Initialize(dir,anchor);err!=nil{t.Fatal(err)}
    if err:=InitializeObservationCursor(dir,anchor);err!=nil{t.Fatal(err)}
    w:=map[string]any{
        "version":VerifiedVolumeBootstrapVersion,
        "volumes":[]map[string]any{{
            "capture_scope_id":volumeScope,
            "journal_id":anchor.JournalID,
            "volume_identity":anchor.VolumeIdentity,
            "original_next_usn":anchor.NextUSN,
            "roots":[]map[string]any{{
                "path":`G:\FI-FirstRun`,
                "scope_id":"source-root-1",
                "identity":records.NTFSObjectIdentity{
                    MethodVersion:"ntfs-file-id/1",
                    FileReferenceNumber:"4",SequenceNumber:"1",
                },
            }},
        }},
    }
    raw,err:=json.Marshal(w)
    if err!=nil{t.Fatal(err)}
    return root,dir,raw
}

func TestSenderStaysStoppedUntilEverySourceVolumeBootstrapVerified(t *testing.T){
    root,_,raw:=verifiedBootstrapActivationFixture(t)
    if err:=VerifyVolumeBootstrapReady(root);!errors.Is(err,os.ErrNotExist){
        t.Fatalf("sender allowed incomplete original capture marker: %v",err)
    }
    path:=filepath.Join(root,VerifiedVolumeBootstrapFile)
    if err:=os.WriteFile(path,raw,0600);err!=nil{t.Fatal(err)}
    if err:=VerifyVolumeBootstrapReady(root);err!=nil{
        t.Fatalf("sender rejected complete gMSA-original source custody: %v",err)
    }
    if err:=os.WriteFile(path,[]byte(`{"version":"fi-volume-bootstrap-verified/1"}`),0600);err!=nil{t.Fatal(err)}
    if err:=VerifyVolumeBootstrapReady(root);err==nil{
        t.Fatal("sender accepted witness with no journal or governed roots")
    }
    if err:=os.WriteFile(path,raw,0600);err!=nil{t.Fatal(err)}
    if err:=os.WriteFile(path,[]byte("{}{}"),0600);err!=nil{t.Fatal(err)}
    if err:=VerifyVolumeBootstrapReady(root);err==nil{
        t.Fatal("sender accepted forged multiple source witnesses")
    }
}

func TestSenderRejectsMissingOrChangedJournalCursors(t *testing.T){
    root,volumeDir,raw:=verifiedBootstrapActivationFixture(t)
    path:=filepath.Join(root,VerifiedVolumeBootstrapFile)
    if err:=os.WriteFile(path,raw,0600);err!=nil{t.Fatal(err)}
    if err:=os.Remove(filepath.Join(volumeDir,observationCursorName));err!=nil{t.Fatal(err)}
    if err:=VerifyVolumeBootstrapReady(root);err==nil{
        t.Fatal("sender started with no separate original observation cursor")
    }
    anchor,err:=readCursor(filepath.Join(volumeDir,captureName));if err!=nil{t.Fatal(err)}
    if err:=InitializeObservationCursor(volumeDir,anchor);err!=nil{t.Fatal(err)}
    other:=anchor;other.JournalID="999"
    if err:=atomicWrite(filepath.Join(volumeDir,captureName),mustJSON(other));err!=nil{t.Fatal(err)}
    if err:=VerifyVolumeBootstrapReady(root);!errors.Is(err,ErrConflict){
        t.Fatalf("sender accepted original volume journal reset: %v",err)
    }
}
