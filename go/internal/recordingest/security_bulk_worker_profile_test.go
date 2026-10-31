// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"testing"
)

func TestWorkerFixedSecurityProfileNamesAndBounds(t *testing.T) {
	base := context.Background()
	if got := FixedSecurityBulkProfileName(base); got != "P1" {
		t.Fatalf("default changed: %q", got)
	}
	for _, tc := range []struct {
		name  string
		count int
		bytes int64
	}{
		{"P1", 1024, 8 << 20},
		{"P2", 2048, 16 << 20},
		{"P3", 4096, 16 << 20},
		{"P4", 8192, 32 << 20},
		{"P5", 16384, 64 << 20},
	} {
		ctx, err := WithFixedSecurityBulkProfile(base, tc.name)
		if err != nil {
			t.Fatal(err)
		}
		actual := securityBulkLimitsFromContext(ctx)
		if actual.Name != tc.name || actual.MaxRecords != tc.count || actual.MaxBytes != tc.bytes {
			t.Fatalf("limits for %s: %+v", tc.name, actual)
		}
		if FixedSecurityBulkProfileName(base) != "P1" {
			t.Fatal("global/default profile mutated")
		}
	}
}

func TestWorkerFixedSecurityProfileRejectsInvalidInput(t *testing.T) {
	for _, name := range []string{"", "p3", "P0", "P6", "P3 ", "adaptive", "P3,P4"} {
		if _, err := WithFixedSecurityBulkProfile(context.Background(), name); err == nil {
			t.Fatalf("accepted invalid profile %q", name)
		}
	}
	if _, err := WithFixedSecurityBulkProfile(nil, "P3"); err == nil {
		t.Fatal("accepted nil context")
	}
}
