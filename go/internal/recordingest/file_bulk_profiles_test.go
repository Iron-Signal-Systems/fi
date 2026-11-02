// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
	"context"
	"testing"
)

func TestFileBulkProfilesAreContextScoped(t *testing.T) {
	base := fileBulkLimitsFromContext(context.Background())
	if base.Name != "F1" || base.SourceMaxRecords != 1024 || base.SourceMaxBytes != 8<<20 ||
		base.ObserveMaxRecords != 1024 || base.ObserveMaxBytes != 8<<20 ||
		base.HashMaxRows != 1024 || base.HashMaxBytes != 2<<20 || base.ChildMaxRows != 1024 {
		t.Fatalf("production F1 file COPY defaults changed: %+v", base)
	}
	for _, tc := range []struct {
		name        string
		sourceRows  int
		sourceBytes int64
		hashBytes   int
		childRows   int
	}{
		{"F1", 1024, 8 << 20, 2 << 20, 1024},
		{"F2", 4096, 16 << 20, 4 << 20, 2048},
		{"F3", 8192, 32 << 20, 8 << 20, 4096},
		{"F4", 16384, 64 << 20, 16 << 20, 4096},
	} {
		ctx, err := withFixedFileBulkProfile(context.Background(), tc.name)
		if err != nil {
			t.Fatal(err)
		}
		got := fileBulkLimitsFromContext(ctx)
		if got.Name != tc.name || got.SourceMaxRecords != tc.sourceRows ||
			got.SourceMaxBytes != tc.sourceBytes || got.ObserveMaxRecords != tc.sourceRows ||
			got.ObserveMaxBytes != tc.sourceBytes || got.HashMaxRows != tc.sourceRows ||
			got.HashMaxBytes != tc.hashBytes || got.ChildMaxRows != tc.childRows {
			t.Fatalf("profile %s: %+v", tc.name, got)
		}
	}
	if unchanged := fileBulkLimitsFromContext(context.Background()); unchanged != base {
		t.Fatalf("profile selection mutated production defaults: %+v", unchanged)
	}
	if _, err := withFixedFileBulkProfile(context.Background(), "F5"); err == nil {
		t.Fatal("unknown profile was accepted")
	}
	if _, err := withFixedFileBulkProfile(nil, "F1"); err == nil {
		t.Fatal("nil context was accepted")
	}
}
