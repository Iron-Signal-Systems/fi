// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import "context"

// P3's established field envelope remains unchanged. Only the explicitly
// selected C1 two-group Security experiment doubles it, without changing
// event/source limits of ordinary P1/P3 or any production path.
func securityFieldCopyRowsForContext(ctx context.Context) int {
    if securityC1COPYExperimentEnabled(ctx) { return 65536 }
	if securityBulkLimitsFromContext(ctx).Name == "P3" {
		return 32768
	}
	return securityFieldCopyMaxRows
}
func securityFieldCopyBytesForContext(ctx context.Context) int64 {
    if securityC1COPYExperimentEnabled(ctx) { return 16 << 20 }
	if securityBulkLimitsFromContext(ctx).Name == "P3" {
		return 8 << 20
	}
	return securityFieldCopyMaxBytes
}
