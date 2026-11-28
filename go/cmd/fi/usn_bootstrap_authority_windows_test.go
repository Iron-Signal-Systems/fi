// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "os"
    "path/filepath"
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
)

func fixtureVolumeBootstrapWitness(t *testing.T) (volumeBootstrapWitness,[]serviceUSNVolumeCapture,map[string]records.NTFSObjectIdentity){
    t.Helper()
    sample:=testVolumeJournal("placeholder","1")
    id,err:=usncapture.VolumeCaptureScopeID(sample.VolumeIdentity)
    if err!=nil{t.Fatal(err)}
    roots:=[]string{`G:\FI-Test`,`G:\FI-Second`}
    identities:=map[string]records.NTFSObjectIdentity{}
    witnessRoots:=make([]volumeBootstrapRoot,0,len(roots))
    for i,root:=range roots{
        identity:=records.NTFSObjectIdentity{
            MethodVersion:"ntfs-file-id/1",
            FileReferenceNumber:strings.TrimSpace(string(rune('2'+i))),
            SequenceNumber:"1",
        }
        identities[root]=identity
        witnessRoots=append(witnessRoots,volumeBootstrapRoot{
            Path:root,ScopeID:configuredScopeID(root),Identity:identity,
        })
    }
    v:=volumeBootstrapWitnessVolume{
        CaptureScopeID:id,JournalID:sample.JournalID,VolumeIdentity:sample.VolumeIdentity,
        OriginalNextUSN:"100",Roots:witnessRoots,
    }
    groups:=[]serviceUSNVolumeCapture{{
        CaptureScopeID:id,RepresentativeRoot:roots[0],
        GovernedRoots:roots,JournalID:sample.JournalID,
        VolumeIdentity:sample.VolumeIdentity,
    }}
    return volumeBootstrapWitness{Version:volumeBootstrapWitnessVersion,
        Volumes:[]volumeBootstrapWitnessVolume{v}},groups,identities
}

func TestVerifiedBootstrapAuthorityBlocksPartialAndChangedRoots(t *testing.T){
    dir:=t.TempDir()
    witness,groups,roots:=fixtureVolumeBootstrapWitness(t)
    if err:=verifyVolumeBootstrapServiceAuthority(dir,groups,roots);err==nil{
        t.Fatal("service activated before every baseline was committed")
    }
    if err:=commitVolumeBootstrapWitness(dir,witness);err!=nil{t.Fatal(err)}
    if err:=verifyVolumeBootstrapServiceAuthority(dir,groups,roots);err!=nil{t.Fatal(err)}
    if err:=commitVolumeBootstrapWitness(dir,witness);err==nil{
        t.Fatal("successful original bootstrap silently overwritten")
    }
    swapped:=[]serviceUSNVolumeCapture{groups[0]}
    swapped[0].GovernedRoots=[]string{`G:\FI-Second`,`G:\FI-Test`}
    if err:=verifyVolumeBootstrapServiceAuthority(dir,swapped,roots);err==nil{
        t.Fatal("historical scope order changed without new baseline")
    }
    modified:=map[string]records.NTFSObjectIdentity{}
    for k,v:=range roots{modified[k]=v}
    modified[`G:\FI-Test`]=records.NTFSObjectIdentity{
        MethodVersion:"ntfs-file-id/1",FileReferenceNumber:"888",SequenceNumber:"1",
    }
    if err:=verifyVolumeBootstrapServiceAuthority(dir,groups,modified);err==nil{
        t.Fatal("new NTFS file ID or reused root permitted to adopt historical source")
    }
    path:=filepath.Join(dir,volumeBootstrapWitnessFile)
    if err:=os.WriteFile(path,[]byte("{}{}"),0600);err!=nil{t.Fatal(err)}
    if err:=verifyVolumeBootstrapServiceAuthority(dir,groups,roots);err==nil{
        t.Fatal("malformed/trailing bootstrap authority accepted")
    }
}
func TestVerifiedBootstrapAuthorityRejectsDuplicatedRootAndVolume(t *testing.T){
    witness,_,_:=fixtureVolumeBootstrapWitness(t)
    witness.Volumes[0].Roots=append(witness.Volumes[0].Roots,witness.Volumes[0].Roots[0])
    if err:=validateVolumeBootstrapWitness(witness);err==nil{
        t.Fatal("duplicate governed root accepted")
    }
    witness,_,_=fixtureVolumeBootstrapWitness(t)
    witness.Volumes=append(witness.Volumes,witness.Volumes[0])
    if err:=validateVolumeBootstrapWitness(witness);err==nil{
        t.Fatal("duplicate volume accepted")
    }
}
