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
// The diagnostic must never determine whether a COPY occurs: the existing
// profile limit check remains authoritative. It only labels its cause.
func TestFISecurityFlushLimitAttributionMatchesP3(t *testing.T) {
	limits, err := securityBulkFixedProfile("P3")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		count int
		buffered, next int64
		flush bool
		reason securityBulkFlushReason
	}{
		{"record_limit", 4096, 1<<20, 1, true, securityFlushRecordLimit},
		{"byte_limit", 1500, (16<<20)-1, 2, true, securityFlushByteLimit},
		{"both_limits", 4096, (16<<20)-1, 2, true, securityFlushBothLimits},
		{"no_flush", 2000, 8<<20, 1, false, 0},
		{"oversize_first_row", 0, 0, 17<<20, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flush := limits.shouldFlushBefore(tt.count, tt.buffered, tt.next)
			if flush != tt.flush {
				t.Fatalf("flush=%v want=%v", flush, tt.flush)
			}
			if flush {
				if got := limits.limitReason(tt.count, tt.buffered, tt.next); got != tt.reason {
					t.Fatalf("reason=%d want=%d", got, tt.reason)
				}
			}
		})
	}
}

// The same statistics span signed batches in a processing chunk, but
// are emitted only after the W128 transaction commits successfully.
func TestFISecurityFlushProfileAggregatesCauseAndByteUsage(t *testing.T) {
	var got securityBulkFlushProfile
	got.note(securityFlushRecordLimit, 0, 0) // no COPY, no count
	got.note(securityFlushByteLimit, 1200, 5<<20)
	got.note(securityFlushCoverage, 2100, 10<<20)
	got.note(securityFlushOtherKind, 500, 2<<20)
	got.note(securityFlushChunkEnd, 1500, 6<<20)
	got.note(securityFlushBatchEnd, 800, 3<<20)
	got.note(securityFlushBothLimits, 3000, 16<<20)
	got.note(securityFlushRecordLimit, 4096, 12<<20)
	if got.Calls != 7 || got.Events != 13196 || got.SourceBytes != 54<<20 ||
		got.MinEvents != 500 || got.MaxEvents != 4096 ||
		got.MinSourceBytes != 2<<20 || got.MaxSourceBytes != 16<<20 ||
		got.RecordLimit != 1 || got.ByteLimit != 1 || got.BothLimits != 1 ||
		got.Coverage != 1 || got.OtherKind != 1 || got.ChunkEnd != 1 || got.BatchEnd != 1 {
		t.Fatalf("unexpected private flush profile: %+v", got)
	}
	reasons := got.RecordLimit + got.ByteLimit + got.BothLimits +
		got.Coverage + got.OtherKind + got.ChunkEnd + got.BatchEnd
	if reasons != got.Calls {
		t.Fatalf("COPY calls=%d but reasons=%d", got.Calls, reasons)
	}
}

