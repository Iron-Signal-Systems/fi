// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"testing"
	"time"
)

func TestNTFSStageTimingIncludesDirectAndNestedObservations(t *testing.T) {
	counters := &ntfsStageTimingCounters{}
	base := context.WithValue(context.Background(), ntfsStageTimingContextKey{}, counters)

	for _, nested := range []bool{false, true} {
		ctx := base
		if nested {
			ctx = context.WithValue(ctx, ntfsNestedStageContextKey{}, true)
		}
		stage := beginNTFSStage(ctx)
		if stage.counters == nil {
			t.Fatalf("NTFS stage recorder disabled for nested=%t", nested)
		}
		time.Sleep(time.Millisecond)
		stage.mark("identity")
		time.Sleep(time.Millisecond)
		stage.mark("file")
		stage.finish()
	}

	if counters.Observations != 2 {
		t.Fatalf("observations=%d, want 2", counters.Observations)
	}
	if counters.Identity <= 0 || counters.File <= 0 {
		t.Fatalf("NTFS stages were not recorded: identity=%s file=%s", counters.Identity, counters.File)
	}
	if counters.Total < counters.accounted() {
		t.Fatalf("total=%s is less than accounted stages=%s", counters.Total, counters.accounted())
	}
}

func TestNTFSStageTimingWithoutCollectorIsInert(t *testing.T) {
	stage := beginNTFSStage(context.Background())
	if stage.counters != nil {
		t.Fatal("unexpected NTFS stage timing collector")
	}
	stage.mark("file")
	stage.finish()
}
