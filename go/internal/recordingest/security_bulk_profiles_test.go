// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"testing"
)

func TestFISecurityBulkFiveFixedProfiles(t *testing.T) {
	tests := []struct {
		name  string
		rows  int
		bytes int64
	}{
		{"P1", 1024, 8 << 20},
		{"P2", 2048, 16 << 20},
		{"P3", 4096, 16 << 20},
		{"P4", 8192, 32 << 20},
		{"P5", 16384, 64 << 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := securityBulkFixedProfile(tt.name)
			if err != nil {
				t.Fatal(err)
			}
			if got.Name != tt.name || got.MaxRecords != tt.rows || got.MaxBytes != tt.bytes {
				t.Fatalf("profile=%+v, want %+v", got, tt)
			}
			ctx, err := withFixedSecurityBulkProfile(context.Background(), tt.name)
			if err != nil {
				t.Fatal(err)
			}
			if fromCtx := securityBulkLimitsFromContext(ctx); fromCtx != got {
				t.Fatalf("profile changed between context and writer: %+v", fromCtx)
			}
			if !got.shouldFlushBefore(tt.rows, 0, 1) || got.shouldFlushBefore(tt.rows-1, 0, 1) {
				t.Fatalf("row cap broken: %+v", got)
			}
			if !got.shouldFlushBefore(1, tt.bytes-1, 2) || got.shouldFlushBefore(1, tt.bytes-1, 1) {
				t.Fatalf("byte cap broken: %+v", got)
			}
			if got.shouldFlushBefore(0, 0, tt.bytes+1) {
				t.Fatal("single oversized valid record would have been dropped or blocked")
			}
		})
	}
}

func TestFISecurityBulkFixedProfileFailClosedAndDefault(t *testing.T) {
	defaults := securityBulkLimitsFromContext(context.Background())
	if defaults.Name != "P1" || defaults.MaxRecords != 1024 || defaults.MaxBytes != 8<<20 {
		t.Fatalf("unexpected production default: %+v", defaults)
	}
	if _, err := withFixedSecurityBulkProfile(context.Background(), "P6"); err == nil {
		t.Fatal("unknown profile was accepted")
	}
	if _, err := withFixedSecurityBulkProfile(nil, "P5"); err == nil {
		t.Fatal("nil context was accepted")
	}
	forged := context.WithValue(context.Background(), securityBulkProfileContextKey{},
		securityBulkLimits{Name: "P5", MaxRecords: 1000000, MaxBytes: 1 << 40})
	if got := securityBulkLimitsFromContext(forged); got != defaults {
		t.Fatalf("unvalidated profile overridden defaults: %+v", got)
	}
	if got := securityBulkLimitsFromContext(nil); got != defaults {
		t.Fatalf("nil context overridden defaults: %+v", got)
	}
}

func TestFISecurityBulkBytesDoNotOverflow(t *testing.T) {
	limits, _ := securityBulkFixedProfile("P5")
	if !limits.shouldFlushBefore(1, limits.MaxBytes-16, int64(1<<62)) {
		t.Fatal("very large source record should trigger buffer flush")
	}
}
