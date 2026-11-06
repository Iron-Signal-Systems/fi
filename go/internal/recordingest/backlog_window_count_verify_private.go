// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
//
// PRIVATE experiment only. Not part of production SoR count verification.
package recordingest

import "context"

type privateIndexedWindowCountVerifyKey struct{}

// WithPrivateIndexedWindowCountVerify selects an alternate per-signed-batch
// count and byte aggregation inside the existing atomic private window. The
// invoking CLI permits this only for isolated deferred verified-clone replay.
func WithPrivateIndexedWindowCountVerify(ctx context.Context) context.Context {
	return context.WithValue(ctx, privateIndexedWindowCountVerifyKey{}, true)
}

func privateIndexedWindowCountVerifyEnabled(ctx context.Context) bool {
	return ctx != nil && ctx.Value(privateIndexedWindowCountVerifyKey{}) == true
}

// Restrict to the authenticated source generation and exact original batch
// identities; aggregate every row in each selected source batch using the
// existing UNIQUE(source_batch_id,record_ordinal) B-tree. MATERIALIZED fixes
// the selected batch list; the correlated LATERAL aggregate prevents a global
// source_record scan. No SET enable_* planner overrides or temporary indexes.
// Keep qualified fi.* tokens for privateProjectionTx's audited rewrite.
const privateIndexedWindowCountVerifySQL = `
WITH selected_batches AS MATERIALIZED (
    SELECT sb.source_batch_id
    FROM fi.source_batch sb
    WHERE sb.recorded_generation_id=$1
      AND sb.batch_id=ANY($2::text[])
)
SELECT coalesce(sum(v.cnt),0)::bigint,
       coalesce(sum(v.bytes),0)::bigint
FROM selected_batches sb
CROSS JOIN LATERAL (
    SELECT count(*)::bigint AS cnt,
           coalesce(sum(sr.record_bytes),0)::bigint AS bytes
    FROM fi.source_record sr
    WHERE sr.source_batch_id=sb.source_batch_id
) v
`
