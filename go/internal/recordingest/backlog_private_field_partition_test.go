// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

package recordingest

import (
	"context"
	"testing"
)

func TestPrivateFieldPartitionControls(t *testing.T) {
	ctx := context.Background()
	if privateSecurityFieldPartitionsEnabled(ctx) || privateSecurityFieldShouldFail(ctx, 2) {
		t.Fatal("private partition or failpoint unexpectedly enabled")
	}
	ctx = WithPrivateSecurityFieldPartitions(ctx)
	if !privateSecurityFieldPartitionsEnabled(ctx) {
		t.Fatal("opt-in lost")
	}
	var err error
	ctx, err = WithPrivateSecurityFieldLateFailure(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !privateSecurityFieldShouldFail(ctx, 2) || privateSecurityFieldShouldFail(ctx, 1) {
		t.Fatal("failpoint wrong window")
	}
	for _, n := range []int{-1, 0, 1000000} {
		if _, err := privateSecurityFieldWindowTable(n); err == nil {
			t.Fatalf("index %d admitted", n)
		}
		if _, err := WithPrivateSecurityFieldLateFailure(ctx, n); err == nil {
			t.Fatalf("failpoint %d admitted", n)
		}
	}
	got, err := privateSecurityFieldWindowTable(2)
	if err != nil || got != "windows_security_event_field_w000002" {
		t.Fatalf("name=%q err=%v", got, err)
	}
}
