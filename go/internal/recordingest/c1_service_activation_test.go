// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "errors"
    "testing"
)

func TestC1ServiceFailsClosedUntilSorIntegration(t *testing.T) {
    if !errors.Is(C1ServiceAdmission(), ErrC1SORNotIntegrated) {
        t.Fatal("pre-C1 ingest worker must not run against the populated SoR")
    }
    _, err:=IngestC1PreparedGeneration(context.Background(),nil,"attempt",nil)
    if !errors.Is(err, ErrC1SORNotIntegrated) {
        t.Fatalf("C1 must not fall back to old SoR processing: %v",err)
    }
}
