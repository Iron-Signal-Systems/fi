// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import "context"

// WithFixedSecurityBulkProfile is the explicitly configured worker boundary
// for a fixed P1-P5 profile. The result is immutable for this generation.
// There is no process-global profile and no adaptive selection here.
// Invalid names and nil contexts fail closed before ingestion begins.
func WithFixedSecurityBulkProfile(ctx context.Context, name string) (context.Context, error) {
	return withFixedSecurityBulkProfile(ctx, name)
}

// FixedSecurityBulkProfileName provides read-only inspection of the effective
// validated profile. An absent selector has always meant conservative P1.
func FixedSecurityBulkProfileName(ctx context.Context) string {
	return securityBulkLimitsFromContext(ctx).Name
}
