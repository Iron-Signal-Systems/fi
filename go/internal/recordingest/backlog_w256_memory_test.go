// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.
package recordingest

import (
	"context"
	"testing"
)

func TestPrivateW256MemoryPressureThresholds(t *testing.T) {
	tests := []struct {
		name string
		rss, managed uint64
		pressure, reject bool
	}{
		{"low", 1 << 30, 1 << 30, false, false},
		{"managed pressure", 1 << 30, privateW256ManagedPressure, true, false},
		{"rss pressure", privateW256RSSPressure, 1 << 30, true, false},
		{"rss abort", privateW256RSSAbort, 1 << 30, false, true},
		{"managed abort", 1 << 30, privateW256RSSAbort, false, true},
		{"below abort", privateW256RSSAbort - 1, 1 << 30, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pressure, err := decideW256Memory(tc.rss, tc.managed)
			if (err != nil) != tc.reject || pressure != tc.pressure {
				t.Fatalf("pressure=%v err=%v, want pressure=%v reject=%v",
					pressure, err, tc.pressure, tc.reject)
			}
		})
	}
}

func TestPrivateW256ChunkCeilingShrinksAtPressure(t *testing.T) {
	for _, n := range []int{32768, 65536, 98304, 131072} {
		ctx, err := WithPrivateW256MemoryBudget(context.Background(), n)
		if err != nil {
			t.Fatal(err)
		}
		gov := privateW256BudgetFromContext(ctx)
		if gov == nil || gov.active != n {
			t.Fatalf("initial chunk=%d governor=%+v", n, gov)
		}
		for i := 0; i < 8; i++ {
			gov.afterChunk(true)
			if gov.active < privateW256MinChunk || gov.active > n {
				t.Fatalf("pressure changed chunk beyond bounds %+v", gov)
			}
		}
		if gov.active != privateW256MinChunk || gov.chunks != 8 || gov.pressureCuts != 8 {
			t.Fatalf("pressure did not cap at K32 %+v", gov)
		}
		gov.afterChunk(false)
		if gov.active != privateW256MinChunk || gov.pressureCuts != 8 {
			t.Fatalf("unproved in-window growth %+v", gov)
		}
	}
	if _, err := WithPrivateW256MemoryBudget(nil, 32768); err == nil {
		t.Fatal("accepted nil context")
	}
	if _, err := WithPrivateW256MemoryBudget(context.Background(), 262144); err == nil {
		t.Fatal("accepted unbounded chunk")
	}
}
