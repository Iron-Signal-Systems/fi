//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "strings"
    "testing"

    "github.com/Iron-Signal-Systems/fi/go/internal/c1handoff"
)

// No database connection or custody read is permitted until the exact,
// complete Start frame and full replay boundary are authenticated.
func TestC1PendingReplayRequiresOriginalFullStart(t *testing.T){
    service:=&C1SoRService{}
    for _,f:=range []c1handoff.Frame{
        {},
        {Kind:c1handoff.Drain,SourceID:"src",GenerationID:"gen",
            ReceiptSHA256:strings.Repeat("a",64)},
        {Kind:c1handoff.Start,SourceID:"src",GenerationID:"gen",
            ReceiptSHA256:strings.Repeat("a",64),StartBatchIndex:1},
    }{
        if allowed,err:=service.c1InspectGovernedPendingReplay(context.Background(),f);
           err==nil||allowed{
            t.Fatalf("C1 pending accepted untrusted replay frame: %t %v",allowed,err)
        }
    }
    if allowed,err:=service.c1InspectGovernedPendingReplay(nil,c1handoff.Frame{Kind:c1handoff.Start});
       err==nil||allowed{
        t.Fatalf("C1 pending accepted nil replay context: %t %v",allowed,err)
    }
}
