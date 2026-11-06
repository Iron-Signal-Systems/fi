// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
    "context"
    "strings"
    "testing"
)

func TestPrivateIndexedWindowCountVerificationIsOptIn(t *testing.T) {
    if privateIndexedWindowCountVerifyEnabled(context.Background()) || privateIndexedWindowCountVerifyEnabled(nil) {
        t.Fatal("indexed verifier unexpectedly enabled without explicit private context")
    }
    ctx := WithPrivateIndexedWindowCountVerify(context.Background())
    if !privateIndexedWindowCountVerifyEnabled(ctx) {
        t.Fatal("private indexed verifier context not enabled")
    }
    for _, required := range []string{
        "WITH selected_batches AS MATERIALIZED",
        "sb.recorded_generation_id=$1",
        "sb.batch_id=ANY($2::text[])",
        "CROSS JOIN LATERAL",
        "sr.source_batch_id=sb.source_batch_id",
        "sum(sr.record_bytes)",
    } {
        if !strings.Contains(privateIndexedWindowCountVerifySQL, required) {
            t.Fatalf("indexed SQL dropped required custody or byte constraint: %s", required)
        }
    }
    rewritten, err := rewritePrivateProjectionStatement(privateIndexedWindowCountVerifySQL)
    if err != nil || !strings.Contains(rewritten, "fi_recovery_projection.source_record") ||
        !strings.Contains(rewritten, "fi_recovery_projection.source_batch") {
        t.Fatalf("private SQL rewrite rejected indexed query: %v", err)
    }
}
