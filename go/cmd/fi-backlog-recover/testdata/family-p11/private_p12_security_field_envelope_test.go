// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "testing"
)

func TestPrivateP12SecurityFieldEnvelopeOnlyChangesPrivateP3(t *testing.T){
    ctx:=context.Background()
    p3,err:=withFixedSecurityBulkProfile(ctx,"P3")
    if err!=nil{t.Fatal(err)}
    if got:=securityFieldCopyRowsForContext(p3);got!=32768{
        t.Fatalf("P12 changed original P3 field rows=%d",got)
    }
    if got:=securityFieldCopyBytesForContext(p3);got!=8<<20{
        t.Fatalf("P12 changed original P3 field bytes=%d",got)
    }
    optimized:=privateP12SecurityFieldEnvelopeContext(p3)
    if got:=securityFieldCopyRowsForContext(optimized);got!=65536{
        t.Fatalf("P12 private P3 field rows=%d want=65536",got)
    }
    if got:=securityFieldCopyBytesForContext(optimized);got!=16<<20{
        t.Fatalf("P12 private P3 field bytes=%d want=16777216",got)
    }
    if got:=securityBulkLimitsFromContext(optimized);got.MaxRecords!=4096||got.MaxBytes!=16<<20{
        t.Fatalf("P12 unexpectedly changed Security source buffer %+v",got)
    }
    if got:=securityFieldCopyRowsForContext(ctx);got!=securityFieldCopyMaxRows{
        t.Fatalf("P12 changed conservative production default %d",got)
    }
    if got:=securityFieldCopyBytesForContext(ctx);got!=securityFieldCopyMaxBytes{
        t.Fatalf("P12 changed conservative production field-byte default %d",got)
    }
    p1,err:=withFixedSecurityBulkProfile(ctx,"P1")
    if err!=nil{t.Fatal(err)}
    if got:=securityFieldCopyRowsForContext(privateP12SecurityFieldEnvelopeContext(p1));got!=securityFieldCopyMaxRows{
        t.Fatalf("P12 opt-in changed P1 field rows=%d",got)
    }
    if got:=securityFieldCopyBytesForContext(privateP12SecurityFieldEnvelopeContext(p1));got!=securityFieldCopyMaxBytes{
        t.Fatalf("P12 opt-in changed P1 field bytes=%d",got)
    }
    if privateP12SecurityFieldEnvelopeSelected(nil)||
        privateP12SecurityFieldEnvelopeSelected(context.Background()){
        t.Fatal("P12 enabled without explicit Security SQL lane context")
    }
}
