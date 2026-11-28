// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package main

import (
    "context"
    "errors"
    "fmt"
    "os"

    "github.com/Iron-Signal-Systems/fi/go/internal/usncapture"
)

// ensureServiceUSNVolumeSourceBootstrap runs from the FICollector SERVICE
// gMSA, not from an administrator's interactive account. It is the only
// first-start path that can cross an empty original-USN directory into a
// completed, source-identity-bound multi-volume verified baseline.
//
// Existing valid evidence is never reset; corrupted/partial original state
// is not automatically rebuilt and no missing journal interval is invented.
func ensureServiceUSNVolumeSourceBootstrap(
    ctx context.Context,snapshot serviceOperationalSnapshot,
    bootstrap func(context.Context)(freshUSNBootstrapSummary,error),
)error{
    if ctx==nil||snapshot.USNMode!="volume-source-v1"||
        snapshot.USNCaptureDir==""||bootstrap==nil{
        return errors.New("FI volume-source first start needs explicit source config and governed gMSA bootstrap")
    }
    if err:=ctx.Err();err!=nil{return err}
    _,err:=loadVolumeBootstrapWitness(snapshot.USNCaptureDir)
    if err==nil{return nil}
    if !errors.Is(err,os.ErrNotExist){
        return fmt.Errorf("%w: existing original USN bootstrap evidence invalid; never reset",usncapture.ErrCorrupt)
    }
    summary,err:=bootstrap(ctx)
    if err!=nil{return fmt.Errorf("FI fresh original-USN baseline failed, original custody retained: %w",err)}
    if summary.Status!="SourceAnchorsInitialized"||len(summary.Volumes)==0{
        return errors.New("FI gMSA bootstrap returned without fully accepted original source witnesses")
    }
    if err:=ctx.Err();err!=nil{return err}
    if _,err:=loadVolumeBootstrapWitness(snapshot.USNCaptureDir);err!=nil{
        return fmt.Errorf("FI source bootstrap did not commit exact immutable service authorization: %w",err)
    }
    return nil
}
