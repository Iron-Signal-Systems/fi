//go:build fi_c1_sor_dev

// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// Original P6 source-bound USN projectors require a generation-scoped capture
// state. fi-sor's ordered C1 handoffs each use a separate SQL transaction;
// cross-handoff state MUST come from durable SQL, never process memory.
package recordingest

import (
    "context"
    "errors"
)

func c1SoRUSNCaptureContext(ctx context.Context,sourceID,generationID string)(context.Context,error){
    if ctx==nil||sourceID==""||generationID==""{
        return nil,errors.New("FI C1 USN: exact signed source and generation required")
    }
    state:=newUSNCaptureState(sourceID,generationID)
    ctx=context.WithValue(ctx,usnCaptureContextKey{},state)
    // Restores only an exact preceding boundary belonging to the same
    // signed source, generation, scope and SHA-256 from already committed
    // Pending SQL. Completion is still verified relationally at Drain.
    ctx=context.WithValue(ctx,backlogUSNCrossWindowContextKey{},true)
    return ctx,nil
}
