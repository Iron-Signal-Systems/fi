// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"context"

	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

// fiSecurityProfileOrDefault preserves the historical P1 behavior of
// programmatic callers that leave the new workerConfig field unset.
// Explicit CLI flags (including P1) must be validated, never normalized.
func fiSecurityProfileOrDefault(configured string) string {
	if configured == "" {
		return "P1"
	}
	return configured
}

// fiFixedSecurityProfileContext validates the fixed choice and makes it
// immutable for this generation. Concurrent sources get independent ctx.
func fiFixedSecurityProfileContext(ctx context.Context, configured string) (context.Context, error) {
	return recordingest.WithFixedSecurityBulkProfile(ctx, fiSecurityProfileOrDefault(configured))
}
