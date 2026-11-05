// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import "context"

// Only P3's independent field writer uses the larger bounded COPY envelope.
// Event/source P3 budgets and all production P1 defaults stay unchanged.
func securityFieldCopyRowsForContext(ctx context.Context) int {
	if securityBulkLimitsFromContext(ctx).Name == "P3" {
		return 32768
	}
	return securityFieldCopyMaxRows
}
func securityFieldCopyBytesForContext(ctx context.Context) int64 {
	if securityBulkLimitsFromContext(ctx).Name == "P3" {
		return 8 << 20
	}
	return securityFieldCopyMaxBytes
}
