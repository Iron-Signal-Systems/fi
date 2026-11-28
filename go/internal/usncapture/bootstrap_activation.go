// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "bytes"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "os"
    "path/filepath"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

const (
    VerifiedVolumeBootstrapVersion = "fi-volume-bootstrap-verified/1"
    VerifiedVolumeBootstrapFile = "volume-bootstrap-verified.json"
)

// VerifyVolumeBootstrapReady is a read-only cross-executable activation gate.
// Only the FICollector gMSA can produce the marker AFTER every original
// journal anchor and per-root baseline passed. A partial/malformed marker is
// never permission for FISender to publish an unanchored generation.
// The FICollector independently checks live journal/root identity at startup.
func VerifyVolumeBootstrapReady(custodyRoot string)error{
    if !filepath.IsAbs(custodyRoot){
        return errors.New("FI volume source sender requires absolute owned capture root")
    }
    path:=filepath.Join(custodyRoot,VerifiedVolumeBootstrapFile)
    info,err:=os.Lstat(path)
    if err!=nil{return fmt.Errorf("FI sender awaiting completed original USN baseline: %w",err)}
    if !info.Mode().IsRegular()||info.Size()<1||info.Size()>1<<20{
        return errors.New("FI sender original volume bootstrap witness must be bounded regular file")
    }
    raw,err:=os.ReadFile(path)
    if err!=nil{return err}
    dec:=json.NewDecoder(bytes.NewReader(raw))
    dec.DisallowUnknownFields()
    var witness struct{
        Version string `json:"version"`
        Volumes []struct{
            CaptureScopeID string `json:"capture_scope_id"`
            JournalID string `json:"journal_id"`
            VolumeIdentity records.VolumeIdentity `json:"volume_identity"`
            OriginalNextUSN string `json:"original_next_usn"`
            Roots []struct{
                Path string `json:"path"`
                ScopeID string `json:"scope_id"`
                Identity records.NTFSObjectIdentity `json:"identity"`
            } `json:"roots"`
        } `json:"volumes"`
    }
    if err:=dec.Decode(&witness);err!=nil{return fmt.Errorf("decode completed original NTFS source witness: %w",err)}
    var extra any
    if err:=dec.Decode(&extra);err!=io.EOF{
        return errors.New("FI source witness trailing data")
    }
    if witness.Version!=VerifiedVolumeBootstrapVersion||len(witness.Volumes)==0{
        return errors.New("FI source witness missing complete versioned journal volume set")
    }
    volumes:=make(map[string]struct{},len(witness.Volumes))
    roots:=make(map[string]struct{})
    for _,v:=range witness.Volumes{
        derived,err:=VolumeCaptureScopeID(v.VolumeIdentity)
        if err!=nil||derived!=v.CaptureScopeID||!canonicalDecimal(v.JournalID)||
            !canonicalDecimal(v.OriginalNextUSN)||len(v.Roots)==0{
            return errors.New("FI sender witness has an invalid original NTFS volume/journal")
        }
        if _,duplicate:=volumes[derived];duplicate{
            return errors.New("FI sender witness duplicates original NTFS volume")
        }
        volumes[derived]=struct{}{}
        for _,root:=range v.Roots{
            if root.Path==""||root.ScopeID==""{
                return errors.New("FI sender witness missing original governed root")
            }
            if err:=records.ValidateNTFSObjectIdentity(root.Identity);err!=nil{return err}
            if _,duplicate:=roots[root.ScopeID];duplicate{
                return errors.New("FI sender witness duplicates original governed root")
            }
            roots[root.ScopeID]=struct{}{}
        }
        cursor,err:=readCursor(filepath.Join(custodyRoot,derived,captureName))
        if err!=nil{return fmt.Errorf("FI sender requires captured volume cursor after successful baseline: %w",err)}
        if cursor.ScopeID!=derived||cursor.JournalID!=v.JournalID||
            cursor.VolumeIdentity!=v.VolumeIdentity{
            return fmt.Errorf("%w: captured source differs from immutable bootstrap witness",ErrConflict)
        }
        processed,err:=readCursor(filepath.Join(custodyRoot,derived,processedName))
        if err!=nil{
            return fmt.Errorf("FI sender original volume has no durable processing cursor: %w",err)
        }
        observed,err:=readCursor(filepath.Join(custodyRoot,derived,observationCursorName))
        if err!=nil{
            return fmt.Errorf("FI sender original volume has no separate NTFS observation cursor: %w",err)
        }
        if !sameIdentity(cursor,processed)||!sameIdentity(cursor,observed){
            return fmt.Errorf("%w: collector source and observation cursors belong to different NTFS journals",ErrConflict)
        }
        capUSN,_:=strictDecimalUSN(cursor.NextUSN)
        procUSN,_:=strictDecimalUSN(processed.NextUSN)
        obsUSN,_:=strictDecimalUSN(observed.NextUSN)
        originalUSN,_:=strictDecimalUSN(v.OriginalNextUSN)
        if originalUSN>capUSN||procUSN>capUSN||obsUSN>capUSN||
            procUSN<originalUSN||obsUSN<originalUSN{
            return fmt.Errorf("%w: FI sender cursor sequence is outside original pre-baseline USN custody",ErrConflict)
        }
    }
    return nil
}
