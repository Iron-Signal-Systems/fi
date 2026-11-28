//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import "testing"

// The C1 renderer, SourceParent, private family router, bounded P6 buffers,
// and typed SQL worker must agree: no source-fact event is silently skipped
// or shunted into an unrelated unordered family.
func TestC1ScopedUSNSourceAdmissionThroughOrderedP6(t *testing.T) {
    kind:="USNScopedCapture"
    if _,ok:=supportedRecordKinds[kind];!ok{
        t.Fatal("USNScopedCapture rejected before original SourceParent")
    }
    if !backlogTypedKindAllowed(kind){
        t.Fatal("USNScopedCapture missing from typed private-window gate")
    }
    family,err:=privateFamilyForRecordKind(kind)
    if err!=nil||family!=privateFamilyUSN{
        t.Fatalf("C1 continuous router not USN family: %v, %v",family,err)
    }
    p6,err:=privateP6KindFamily(kind)
    if err!=nil||p6!=privateP6USN{
        t.Fatalf("C1 P6 buffering not ordered USN: %v, %v",p6,err)
    }
}
