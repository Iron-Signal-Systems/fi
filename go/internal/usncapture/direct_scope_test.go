// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package usncapture

import (
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/records"
)

func TestDirectParentScopeFromOriginalUSNOnly(t *testing.T){
    batch,root:=scopeTestBatch()
    batch.Records[0].ParentIdentity=root
    selected,err:=SelectCapturedScope(batch,"root-test",root,
        DirectRootScopeResolver("root-test",batch.JournalID,root))
    if err!=nil||selected.Governed!=1||selected.Unresolved!=0||
        selected.Excluded!=0||selected.Included[0].Class!=ScopeGoverned{
        t.Fatalf("journal parent proof not used: %+v %v",selected,err)
    }
}
func TestNestedOrMovedObjectWithoutDurableAncestryRemainsUnresolved(t *testing.T){
    batch,root:=scopeTestBatch()
    batch.Records=append(batch.Records,records.USNChangeObservation{
        FileIdentity:scopeTestIdentity("3"),
        ParentIdentity:scopeTestIdentity("100"),
        USN:"160",
    })
    selected,err:=SelectCapturedScope(batch,"root-test",root,
        DirectRootScopeResolver("root-test",batch.JournalID,root))
    if err!=nil||selected.Unresolved!=2||selected.Excluded!=0||
        len(selected.Included)!=2{
        t.Fatalf("missing historical ancestry wrongly excluded changes: %+v %v",selected,err)
    }
}
