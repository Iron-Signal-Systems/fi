// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "bytes"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "reflect"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
    "github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
)

const (
    volumeBootstrapWitnessVersion = "fi-volume-bootstrap-verified/1"
    volumeBootstrapWitnessFile = "volume-bootstrap-verified.json"
    maxVolumeBootstrapWitnessBytes = 1 << 20
)

// These are original per-root source identities and pre-baseline USN positions,
// not assertions that the baseline can reconstruct earlier NTFS history.
type volumeBootstrapRoot struct {
    Path string `json:"path"`
    ScopeID string `json:"scope_id"`
    Identity records.NTFSObjectIdentity `json:"identity"`
}
type volumeBootstrapWitnessVolume struct {
    CaptureScopeID string `json:"capture_scope_id"`
    JournalID string `json:"journal_id"`
    VolumeIdentity records.VolumeIdentity `json:"volume_identity"`
    OriginalNextUSN string `json:"original_next_usn"`
    Roots []volumeBootstrapRoot `json:"roots"`
}
type volumeBootstrapWitness struct {
    Version string `json:"version"`
    Volumes []volumeBootstrapWitnessVolume `json:"volumes"`
}

func validateVolumeBootstrapWitness(w volumeBootstrapWitness) error {
    if w.Version!=volumeBootstrapWitnessVersion || len(w.Volumes)==0 {
        return errors.New("FI verified volume bootstrap witness version/volumes invalid")
    }
    visited:=map[string]struct{}{}
    roots:=map[string]struct{}{}
    for _,v:=range w.Volumes{
        id,err:=usncapture.VolumeCaptureScopeID(v.VolumeIdentity)
        if err!=nil || id!=v.CaptureScopeID || v.JournalID=="" ||
            v.OriginalNextUSN=="" || len(v.Roots)==0{
            return errors.New("FI verified volume bootstrap source identity invalid")
        }
        if _,exists:=visited[v.CaptureScopeID];exists{
            return errors.New("FI verified volume bootstrap duplicated volume")
        }
        visited[v.CaptureScopeID]=struct{}{}
        for _,root:=range v.Roots{
            if root.Path==""||root.ScopeID==""{
                return errors.New("FI verified volume bootstrap missing governed root")
            }
            if _,exists:=roots[root.ScopeID];exists{
                return errors.New("FI verified volume bootstrap duplicated governed scope")
            }
            roots[root.ScopeID]=struct{}{}
            if err:=records.ValidateNTFSObjectIdentity(root.Identity);err!=nil{return err}
        }
    }
    return nil
}

// commitVolumeBootstrapWitness is the final and sole activation boundary.
// Bootstrap must have already checked all baselines and every current capture
// cursor, and the service still re-checks its current source identities.
// The marker never overwrites prior authority or silently resumes a partial
// earlier bootstrap.
func commitVolumeBootstrapWitness(queueRoot string,w volumeBootstrapWitness) error {
    if err:=validateVolumeBootstrapWitness(w);err!=nil{return err}
    if !filepath.IsAbs(queueRoot){return errors.New("FI source custody root must be absolute")}
    path:=filepath.Join(queueRoot,volumeBootstrapWitnessFile)
    if _,err:=os.Lstat(path);err==nil{
        return errors.New("FI verified volume bootstrap authority already exists; will not overwrite")
    }else if !errors.Is(err,os.ErrNotExist){return err}
    encoded,err:=json.Marshal(w)
    if err!=nil{return err}
    if len(encoded)>maxVolumeBootstrapWitnessBytes{
        return errors.New("FI verified volume bootstrap authority exceeds bounded size")
    }
    file,err:=os.CreateTemp(queueRoot,".fi-bootstrap-pending-")
    if err!=nil{return err}
    defer os.Remove(file.Name())
    if err:=file.Chmod(0600);err!=nil{_ =file.Close();return err}
    if _,err:=file.Write(encoded);err!=nil{_ =file.Close();return err}
    if err:=file.Sync();err!=nil{_ =file.Close();return err}
    if err:=file.Close();err!=nil{return err}
    if _,err:=os.Lstat(path);err==nil{return errors.New("FI bootstrap authority appeared before publication")}
    if err:=os.Rename(file.Name(),path);err!=nil{return err}
    return nil
}

func loadVolumeBootstrapWitness(queueRoot string)(volumeBootstrapWitness,error){
    path:=filepath.Join(queueRoot,volumeBootstrapWitnessFile)
    info,err:=os.Lstat(path)
    if err!=nil{return volumeBootstrapWitness{},fmt.Errorf("FI source service requires fully verified fresh bootstrap: %w",err)}
    if !info.Mode().IsRegular() || info.Size()==0 || info.Size()>maxVolumeBootstrapWitnessBytes{
        return volumeBootstrapWitness{},errors.New("FI volume bootstrap authority must be bounded regular file")
    }
    raw,err:=os.ReadFile(path)
    if err!=nil{return volumeBootstrapWitness{},err}
    decoder:=json.NewDecoder(bytes.NewReader(raw))
    decoder.DisallowUnknownFields()
    var w volumeBootstrapWitness
    if err:=decoder.Decode(&w);err!=nil{return volumeBootstrapWitness{},err}
    var trailing any
    if err:=decoder.Decode(&trailing);err!=io.EOF{
        return volumeBootstrapWitness{},errors.New("FI volume bootstrap authority has trailing data")
    }
    if err:=validateVolumeBootstrapWitness(w);err!=nil{return volumeBootstrapWitness{},err}
    return w,nil
}

// The ordered configured roots and actual live NTFS journal/root identities
// must match the original completed bootstrap exactly. This validation is a
// prerequisite to opening a source queue, not a best-effort warning.
func verifyVolumeBootstrapServiceAuthority(
    queueRoot string,groups []serviceUSNVolumeCapture,
    currentRootIdentities map[string]records.NTFSObjectIdentity,
) error {
    w,err:=loadVolumeBootstrapWitness(queueRoot)
    if err!=nil{return err}
    if len(groups)!=len(w.Volumes){
        return fmt.Errorf("%w: governed volume set changed after bootstrap",usncapture.ErrConflict)
    }
    for i,group:=range groups{
        v:=w.Volumes[i]
        if v.CaptureScopeID!=group.CaptureScopeID ||
            v.JournalID!=group.JournalID ||
            !reflect.DeepEqual(v.VolumeIdentity,group.VolumeIdentity)||
            len(v.Roots)!=len(group.GovernedRoots){
            return fmt.Errorf("%w: source volume/journal/root count differs from completed baseline",
                usncapture.ErrConflict)
        }
        for j,path:=range group.GovernedRoots{
            r:=v.Roots[j]
            current,ok:=currentRootIdentities[path]
            if !ok || path!=r.Path || r.ScopeID!=configuredScopeID(path) ||
                current!=r.Identity{
                return fmt.Errorf("%w: governed root %q changed after verified baseline",
                    usncapture.ErrConflict,path)
            }
        }
    }
    return nil
}
