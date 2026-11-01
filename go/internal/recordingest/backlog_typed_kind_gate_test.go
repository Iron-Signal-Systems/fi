// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import "testing"

// Every presently supported source kind is reviewed for the private typed
// window path. New kinds must not silently gain private recovery authority.
func TestBacklogTypedKindAdmissionIsExplicit(t *testing.T) {
    allowed := map[string]bool{
        "NTFSCollectionError": true,
        "SupportingSourceCollectionError": true,
        "WindowsSecurityEvent": true,
    }
    kinds:=SupportedRecordKinds()
    if len(kinds)!=13 {t.Fatalf("FI added or removed a record kind: review backlog admission (got %d)",len(kinds))}
    for _,kind:=range kinds {
        if backlogTypedKindAllowed(kind)!=allowed[kind] {
            t.Errorf("unsupported or missing typed-window kind admission %q",kind)
        }
    }
    if backlogTypedKindAllowed("")||backlogTypedKindAllowed("UnknownSourceKind") {
        t.Fatal("unknown record kind admitted to private typed projection")
    }
}
