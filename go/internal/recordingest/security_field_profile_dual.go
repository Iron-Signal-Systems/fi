// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import "context"

// P3's child-field COPY has an independent row/byte budget.
// The larger envelope is opt-in ONLY for the private detached-field W128
// experiment. Its source/event budgets, normal P3 behavior, and production P1
// limits remain unchanged. This is a measured candidate, not a new default.
const (
	privateP3FieldCopyMaxRows  = 65_536
	privateP3FieldCopyMaxBytes = 16 << 20
	standardP3FieldCopyMaxRows = 32_768
	standardP3FieldCopyMaxBytes = 8 << 20
)

func securityFieldCopyRowsForContext(ctx context.Context) int {
	if securityBulkLimitsFromContext(ctx).Name == "P3" {
		if ctx != nil && privateSecurityFieldPartitionsEnabled(ctx) {
			return privateP3FieldCopyMaxRows
		}
		return standardP3FieldCopyMaxRows
	}
	return securityFieldCopyMaxRows
}

func securityFieldCopyBytesForContext(ctx context.Context) int64 {
	if securityBulkLimitsFromContext(ctx).Name == "P3" {
		if ctx != nil && privateSecurityFieldPartitionsEnabled(ctx) {
			return privateP3FieldCopyMaxBytes
		}
		return standardP3FieldCopyMaxBytes
	}
	return securityFieldCopyMaxBytes
}
