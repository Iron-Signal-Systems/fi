// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"fmt"
)

// securityBulkLimits describe the bounded number and byte budget of *source*
// WindowsSecurityEvent records retained before one relational COPY sequence.
// Child field rows have independent limits in security_field_copy_source.go.
// All limits apply within one source batch and one generation transaction.
// The byte budget measures recorded input bytes, not PostgreSQL WAL or memory.
type securityBulkLimits struct {
	Name       string
	MaxRecords int
	MaxBytes   int64
}

type securityBulkProfileContextKey struct{}

// securityBulkFixedProfile rejects unknown names instead of silently choosing
// a resource-intensive profile. No mutable process-wide tuning state exists.
func securityBulkFixedProfile(name string) (securityBulkLimits, error) {
	switch name {
	case "P1":
		return securityBulkLimits{Name: "P1", MaxRecords: securityBulkMaxRecords, MaxBytes: securityBulkMaxBytes}, nil
	case "P2":
		return securityBulkLimits{Name: "P2", MaxRecords: 2048, MaxBytes: 16 << 20}, nil
	case "P3":
		return securityBulkLimits{Name: "P3", MaxRecords: 4096, MaxBytes: 16 << 20}, nil
	case "P4":
		return securityBulkLimits{Name: "P4", MaxRecords: 8192, MaxBytes: 32 << 20}, nil
	case "P5":
		return securityBulkLimits{Name: "P5", MaxRecords: 16384, MaxBytes: 64 << 20}, nil
	default:
		return securityBulkLimits{}, fmt.Errorf("FI unknown Windows Security bulk profile %q", name)
	}
}

// withFixedSecurityBulkProfile is an internal acceptance/benchmark seam. The
// production caller does not set this context value and always uses P1.
// Profile changes must occur before generation ingestion begins; this is not
// an adaptive controller and does not permit changing limits mid-batch.
func withFixedSecurityBulkProfile(ctx context.Context, name string) (context.Context, error) {
	if ctx == nil {
		return nil, fmt.Errorf("FI Windows Security bulk profile: nil context")
	}
	selected, err := securityBulkFixedProfile(name)
	if err != nil {
		return nil, err
	}
	return context.WithValue(ctx, securityBulkProfileContextKey{}, selected), nil
}

// securityBulkLimitsFromContext is deterministic and never reads environment
// variables or host resources. Only the package-private, validated context
// selector used in acceptance tests can override the conservative default.
func securityBulkLimitsFromContext(ctx context.Context) securityBulkLimits {
	if ctx != nil {
		if selected, ok := ctx.Value(securityBulkProfileContextKey{}).(securityBulkLimits); ok {
			if canonical, err := securityBulkFixedProfile(selected.Name); err == nil && canonical == selected {
				return selected
			}
		}
	}
	selected, _ := securityBulkFixedProfile("P1")
	return selected
}

// shouldFlushBefore adds a new source record only when doing so would exceed
// the selected profile or the existing buffer is already full. A single valid
// oversized record is intentionally allowed by the legacy ingest contract;
// it must not be split, silently discarded, or wrapped by arithmetic overflow.
func (limits securityBulkLimits) shouldFlushBefore(count int, bufferedBytes int64, nextBytes int64) bool {
	if count >= limits.MaxRecords {
		return true
	}
	return count > 0 && nextBytes > limits.MaxBytes-bufferedBytes
}
