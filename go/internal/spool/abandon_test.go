// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package spool

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
)

func TestAbandonDoesNotPublishIncompleteSourceBatch(t *testing.T){
    ResetPolicyForTesting(t)
    dir:=filepath.Join(t.TempDir(),"fi-spool")
    writer,err:=NewWriter(dir,512,CollectorIdentity{
        ExecutablePath:"CI-FICollector",
        ExecutableSHA256:strings.Repeat("a",64),
    })
    if err!=nil{t.Fatal(err)}
    if err:=writer.Append("USNScopedCapture","root-ci",map[string]any{
        "version":"ci-test-only",
    });err!=nil{t.Fatal(err)}
    if err:=writer.Abandon();err!=nil{t.Fatal(err)}
    if err:=writer.Abandon();err!=nil{t.Fatalf("abandon idempotence: %v",err)}
    if len(writer.FinalizedBatches())!=0{
        t.Fatal("abandoned source was reported verified")
    }
    for _,pattern:=range []string{"batch-*.jsonl","batch-*.manifest.json"}{
        matches,err:=filepath.Glob(filepath.Join(dir,pattern))
        if err!=nil{t.Fatal(err)}
        if len(matches)!=0{t.Fatalf("abandoned source leaked to sender spool: %v",matches)}
    }
    work,err:=CollectorWorkDir(dir)
    if err!=nil{t.Fatal(err)}
    entries,err:=os.ReadDir(work)
    if err!=nil{t.Fatal(err)}
    open:=0
    for _,e:=range entries{
        if strings.HasSuffix(e.Name(),".open"){open++}
    }
    if open!=1{t.Fatalf("abandoned source work unavailable for quarantine: %d",open)}
}
