// Copyright (c) 2026 John Joseph Wood. All rights reserved.
// Use of this source code is governed by the File Intelligence (FI)
// Source Review License, Version 1.0, found in the repository root LICENSE file.

//go:build windows

package usn

import "testing"

func TestReobserveWorkerRuntimeConfiguration(t *testing.T) {
	prior := currentReobserveWorkers()
	t.Cleanup(func() {
		if err := ConfigureReobserveWorkers(prior); err != nil {
			t.Errorf("restore worker count: %v", err)
		}
	})
	for _, value := range []int{1, 2, 4, 8, 16} {
		if err := ConfigureReobserveWorkers(value); err != nil {
			t.Fatalf("workers=%d rejected: %v", value, err)
		}
		if got := currentReobserveWorkers(); got != value {
			t.Fatalf("workers=%d want=%d", got, value)
		}
	}
	for _, value := range []int{-1, 0, 17, 64} {
		if err := ConfigureReobserveWorkers(value); err == nil {
			t.Fatalf("workers=%d unexpectedly accepted", value)
		}
	}
	if currentReobserveWorkers() != 16 {
		t.Fatal("invalid worker configuration mutated live setting")
	}
}
