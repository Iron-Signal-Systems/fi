//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "testing"
)

// The operational fi-ingest/fi-sor split must not silently fall back to P3
// after the approved full-generation C1 P4 benchmark was frozen.
func TestC1NativeJailPathRetainsFrozenSecurityParameters(t *testing.T){
    t.Setenv("FI_C1_SECURITY_8G_EXPERIMENT","")
    t.Setenv("FI_C1_SECURITY_FULL_BACKLOG_CANDIDATE","")
    sink:=&c1SQLHandoffTestSink{}
    buffers,err:=newC1NativeP6Buffers(1,sink)
    if err!=nil{t.Fatal(err)}
    c:=buffers.lanes[privateP6Security].limit
    if c.rows!=8192||c.bytes!=32<<20{
        t.Fatalf("native C1 Security family diverges from frozen P4: %+v",c)
    }
    if buffers.source.limit.rows!=8192||buffers.source.limit.bytes!=64<<20{
        t.Fatalf("frozen ordered SourceParent bound changed: %+v",buffers.source.limit)
    }
    ctx:=context.WithValue(context.Background(),c1NativeFrozenSecurityContextKey{},true)
    active,err:=privateC1FrozenSecuritySelected(ctx)
    if err!=nil||!active{t.Fatalf("native C1 failed frozen Security selection: %v",err)}
    ctx,err=withFixedSecurityBulkProfile(ctx,"P4")
    if err!=nil{t.Fatal(err)}
    ctx=withC1SecurityCOPYExperiment(ctx)
    if got:=securityFieldCopyRowsForContext(ctx);got!=65536{
        t.Fatalf("frozen Security child field COPY rows=%d want 65536",got)
    }
    if got:=securityFieldCopyBytesForContext(ctx);got!=16<<20{
        t.Fatalf("frozen Security child field COPY bytes=%d want 16 MiB",got)
    }
    control,err:=privateC1FrozenSecuritySelected(context.Background())
    if err!=nil||control{
        t.Fatalf("unselected clone unexpectedly activated P4: %t %v",control,err)
    }
}
