// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usncapture

import (
    "os"
    "path/filepath"
    "testing"
)

func TestCaptureOwnerExcludesSecondCollector(t *testing.T) {
    dir:=filepath.Join(t.TempDir(),"capture")
    if err:=os.Mkdir(dir,0700);err!=nil{t.Fatal(err)}
    first,err:=AcquireCaptureOwner(dir)
    if err!=nil{t.Fatal(err)}
    if second,err:=AcquireCaptureOwner(dir);err==nil{
        _=second.Close()
        _=first.Close()
        t.Fatal("two FI collectors acquired the same volume capture queue")
    }
    if err:=first.Close();err!=nil{t.Fatal(err)}
    next,err:=AcquireCaptureOwner(dir)
    if err!=nil{t.Fatalf("volume owner not recoverable after close: %v",err)}
    if err:=next.Close();err!=nil{t.Fatal(err)}
}
func TestCaptureOwnerRejectsUninitializedOrSymlinkedRoot(t *testing.T){
    dir:=filepath.Join(t.TempDir(),"not-initialized")
    if _,err:=AcquireCaptureOwner(dir);err==nil{
        t.Fatal("missing queue directory was silently created")
    }
    if _,err:=AcquireCaptureOwner("relative");err==nil{
        t.Fatal("relative queue directory accepted")
    }
}
