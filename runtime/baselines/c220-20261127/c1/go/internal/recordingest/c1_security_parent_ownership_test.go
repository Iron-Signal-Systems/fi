//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// The ordered C1 SourceParent SQL writer alone owns committed parent rows.
// The non-C1 Security bulk path retains its original source COPY behavior.
package recordingest

import (
    "context"
    "testing"
)

func TestC1SecuritySourceParentOwnershipIsExplicit(t *testing.T) {
    base := context.Background()
    if privateP6SourceAlreadyInserted(base) {
        t.Fatal("ordinary Security bulk silently skipped its source COPY")
    }
    other := context.WithValue(base, struct{ Name string }{"unrelated"}, true)
    if privateP6SourceAlreadyInserted(other) {
        t.Fatal("unrelated context granted parent ownership")
    }
    granted := context.WithValue(base, privateP6SourceAlreadyInsertedKey{}, true)
    if !privateP6SourceAlreadyInserted(granted) {
        t.Fatal("C1 committed parent context failed to stop duplicate Security source COPY")
    }
    notGranted := context.WithValue(base, privateP6SourceAlreadyInsertedKey{}, false)
    if privateP6SourceAlreadyInserted(notGranted) {
        t.Fatal("uncommitted parent context suppressed ordinary Security source COPY")
    }
}
