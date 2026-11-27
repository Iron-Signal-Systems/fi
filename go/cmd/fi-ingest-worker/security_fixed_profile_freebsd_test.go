// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build freebsd

package main

import (
	"context"
	"testing"

	"github.com/Iron-Signal-Systems/fi/go/internal/recordingest"
)

func TestFIFixedProfileWorkerContext(t *testing.T) {
	base := context.Background()
	for _, tc := range []struct{ selected, expected string }{
		{"", "P1"}, {"P1", "P1"}, {"P3", "P3"}, {"P5", "P5"},
	} {
		ctx, err := fiFixedSecurityProfileContext(base, tc.selected)
		if err != nil {
			t.Fatal(err)
		}
		if got := recordingest.FixedSecurityBulkProfileName(ctx); got != tc.expected {
			t.Fatalf("configured=%q got=%q", tc.selected, got)
		}
		if got := recordingest.FixedSecurityBulkProfileName(base); got != "P1" {
			t.Fatalf("parent context changed: %q", got)
		}
	}
}

func TestFIFixedProfileWorkerRejectsInvalid(t *testing.T) {
	for _, selected := range []string{"p3", "P0", "P6", "P3 ", "adaptive"} {
		if _, err := fiFixedSecurityProfileContext(context.Background(), selected); err == nil {
			t.Fatalf("accepted invalid profile %q", selected)
		}
	}
	if _, err := fiFixedSecurityProfileContext(nil, "P3"); err == nil {
		t.Fatal("nil context accepted")
	}
}
